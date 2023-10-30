use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{File, read_dir};
use std::io::{BufRead, BufReader, copy};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use glob::glob;
use lazy_static::lazy_static;
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState};
use regex::Regex;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use sysinfo::{Pid, Process, ProcessExt, System, SystemExt};
use xml::reader::{EventReader, XmlEvent};

#[derive(PartialEq)]
enum ProcessType {
    Nginx,
    Apache2,
    Tomcat,
    WebLogic,
    Docker,
    Unknown,
}

impl std::fmt::Display for ProcessType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessType::Nginx => write!(f, "Nginx"),
            ProcessType::Apache2 => write!(f, "Apache2"),
            ProcessType::Tomcat => write!(f, "Tomcat"),
            ProcessType::WebLogic => write!(f, "WebLogic"),
            ProcessType::Docker => write!(f, "Docker"),
            ProcessType::Unknown => write!(f, "Unknown"),
        }
    }
}

lazy_static! {
    static ref ANALYZED_FILES: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
}

#[derive(Clone, Serialize, Deserialize)]
struct Url {
    pathname: String,
    checksum: String,
}

#[derive(Serialize, Deserialize)]
struct Service {
    port: u16,
    pid: u32,
    #[serde(rename = "type")]
    service_type: String,
    command: String,
    urls: Vec<Url>,
}

#[derive(Serialize, Deserialize)]
struct ServiceList {
    services: Vec<Service>,
}

fn check_process_type(command: String) -> ProcessType {
    if command.contains("nginx") {
        return ProcessType::Nginx;
    } else if command.contains("apache2") {
        return ProcessType::Apache2;
    } else if command.contains("tomcat") {
        return ProcessType::Tomcat;
    } else if command.contains("weblogic") {
        return ProcessType::WebLogic;
    } else if command.contains("docker") {
        return ProcessType::Docker;
    }
    return ProcessType::Unknown;
}

fn calculate_checksum(path: &Path) -> String {
    // return path.to_str().unwrap().to_string();
    match File::open(path) {
        Ok(mut file) => {
            let mut hasher = Sha256::new();
            match copy(&mut file, &mut hasher) {
                Ok(_) => {
                    let hash = hasher.finalize();
                    return format!("{:x}", hash);
                }
                Err(_) => {}
            }
        }
        Err(_) => {}
    }
    return "".to_string();
}

fn get_urls(location: &str, root_path: &PathBuf) -> Vec<Url> {
    let mut result: Vec<Url> = Vec::new();
    match read_dir(root_path) {
        Ok(entries) => {
            for entry in entries {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    let sub_location = format!("{}/{}", location, path.strip_prefix(root_path).unwrap().to_str().unwrap());
                    result.extend(get_urls(&sub_location, &path));
                } else if path.is_file() {
                    let rel_path = path.strip_prefix(root_path).unwrap();
                    let mut pathname = format!("{}/{}", location, rel_path.to_str().unwrap());
                    pathname = pathname.replace("//", "/");
                    let url = Url {
                        pathname,
                        checksum: calculate_checksum(&path),
                    };
                    result.push(url);
                }
            }
        }
        Err(_) => {}
    }
    return result;
}

fn get_urls_with_regex(location: &str, root_path: &PathBuf, regex_str: &str) -> Vec<Url> {
    let mut result: Vec<Url> = Vec::new();
    match read_dir(root_path) {
        Ok(entries) => {
            let re = Regex::new(regex_str).unwrap();
            for entry in entries {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    let sub_location = format!("{}/{}", location, path.strip_prefix(root_path).unwrap().to_str().unwrap());
                    result.extend(get_urls_with_regex(&sub_location, &path, regex_str));
                } else if path.is_file() {
                    if re.is_match(path.to_str().unwrap()) {
                        let rel_path = path.strip_prefix(root_path).unwrap();
                        let mut pathname = format!("{}/{}", location, rel_path.to_str().unwrap());
                        pathname = pathname.replace("//", "/");
                        let url = Url {
                            pathname,
                            checksum: calculate_checksum(&path),
                        };
                        result.push(url);
                    }
                }
            }
        }
        Err(_) => {}
    }
    return result;
}

fn get_urls_without_regex(location: &str, root_path: &PathBuf, regex_str: &str) -> Vec<Url> {
    let mut result: Vec<Url> = Vec::new();
    match read_dir(root_path) {
        Ok(entries) => {
            let re = Regex::new(regex_str).unwrap();
            for entry in entries {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    let sub_location = format!("{}/{}", location, path.strip_prefix(root_path).unwrap().to_str().unwrap());
                    result.extend(get_urls_without_regex(&sub_location, &path, regex_str));
                } else if path.is_file() {
                    if !re.is_match(path.to_str().unwrap()) {
                        let rel_path = path.strip_prefix(root_path).unwrap();
                        let mut pathname = format!("{}/{}", location, rel_path.to_str().unwrap());
                        pathname = pathname.replace("//", "/");
                        let url = Url {
                            pathname,
                            checksum: calculate_checksum(&path),
                        };
                        result.push(url);
                    }
                }
            }
        }
        Err(_) => {}
    }
    return result;
}

fn get_nginx_urls(conf_path: &PathBuf, work_dir: &Path) -> Option<HashMap<u16, Vec<Url>>> {
    let mut result: HashMap<u16, Vec<Url>> = HashMap::new();
    let mut paren_stack = Vec::new();
    let mut http_block = Vec::new();
    let mut server_block = Vec::new();
    let mut server_port: u16 = 0;
    let mut location_line = "";

    if let Ok(file) = File::open(&conf_path) {
        let reader = BufReader::new(file);

        // 读http块
        for line in reader.lines() {
            if let Ok(line) = line {
                if line.is_empty() {
                    continue;
                }
                let pure_line = line.trim();
                if pure_line.starts_with('#') {
                    continue;
                }
                if paren_stack.len() == 0 && !pure_line.starts_with("http {") {
                    continue;
                }

                if pure_line.contains("{") {
                    paren_stack.push(true);
                }
                if pure_line.contains("}") {
                    paren_stack.pop();
                }

                if pure_line.starts_with("include") {
                    let mut include_path = pure_line.split_whitespace().nth(1).unwrap().trim_end_matches(';').to_string();

                    if let Some(config_dir) = conf_path.parent() {
                        include_path = config_dir.join(include_path).display().to_string();
                    }

                    // for entry in glob(include_path.as_str()).expect("Failed to read glob pattern") {
                    for entry in glob(include_path.as_str()).ok()? {
                        match entry {
                            Ok(include_file_path) => {
                                if let Ok(include_file) = File::open(&include_file_path) {
                                    let include_file_reader = BufReader::new(include_file);
                                    for include_file_line in include_file_reader.lines() {
                                        if let Ok(include_file_line) = include_file_line {
                                            if include_file_line.is_empty() {
                                                continue;
                                            }
                                            let pure_include_line = include_file_line.trim();
                                            if pure_include_line.starts_with('#') {
                                                continue;
                                            }
                                            http_block.push(pure_include_line.to_string());
                                        }
                                    }
                                }
                            }
                            Err(_) => {}
                        }
                    }
                } else {
                    http_block.push(pure_line.to_string());
                }
            }
        }

        // 解析http块
        for http_line in &http_block {
            if paren_stack.len() == 0 && !http_line.starts_with("server {") {
                continue;
            }
            if http_line.contains("{") {
                server_block.push(http_line);
                paren_stack.push(true);
            }
            if http_line.contains("}") {
                server_block.push(http_line);
                paren_stack.pop();
                if paren_stack.len() == 0 {
                    let mut urls: Vec<Url> = Vec::new();
                    for s in server_block {
                        if s.starts_with("location") {
                            location_line = s;
                        }
                        if s.starts_with("root") {
                            if location_line.is_empty() {
                                location_line = "location / {";
                            }
                            let mut pure_root = s.trim_start_matches("root").trim();
                            pure_root = match pure_root.split_once(';') {
                                Some((result, _)) => result,
                                None => "",
                            };

                            let mut pure_location = location_line.trim_start_matches("location").trim();
                            pure_location = match pure_location.split_once('{') {
                                Some((result, _)) => result.trim(),
                                None => "",
                            };

                            if !pure_root.is_empty() && !pure_location.is_empty() {
                                let len = pure_location.split_whitespace().count();
                                match len {
                                    1 => {
                                        let mut root_path = PathBuf::from(pure_root);
                                        if !root_path.is_absolute() {
                                            root_path = work_dir.join(root_path);
                                        }
                                        urls.extend(get_urls(pure_location, &root_path));
                                    }
                                    2 => {
                                        let symbol = pure_location.split_whitespace().nth(0).unwrap();
                                        let pattern = pure_location.split_whitespace().nth(1).unwrap();
                                        let mut root_path = PathBuf::from(pure_root);
                                        if !root_path.is_absolute() {
                                            root_path = work_dir.join(root_path);
                                        }

                                        match symbol {
                                            "=" => {
                                                let file_path = root_path.join(pattern.strip_prefix('/').unwrap());
                                                let url = Url {
                                                    pathname: pattern.to_string(),
                                                    checksum: calculate_checksum(&file_path),
                                                };
                                                urls.push(url);
                                            }
                                            "^~" => {
                                                urls.extend(get_urls(pattern, &root_path));
                                            }
                                            "~*" => {
                                                let regex_str = format!("(?i){}", pattern);
                                                urls.extend(get_urls_with_regex("/", &root_path, &regex_str));
                                            }
                                            "~" => {
                                                urls.extend(get_urls_with_regex("/", &root_path, pattern));
                                            }
                                            _ => {}
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            location_line = "";
                        }
                    }
                    result.insert(server_port, urls);

                    server_block = vec![];
                    server_port = 0;
                }
            }
            if http_line.starts_with("listen") {
                let ip_port = http_line.split_whitespace().nth(1).unwrap().trim_end_matches(';');
                let port = match ip_port.rsplit_once(':') {
                    Some((_, port)) => port,
                    None => ip_port,
                };
                match port.parse::<u16>() {
                    Ok(port) => server_port = port,
                    Err(_) => {}
                }
            }
            if http_line.starts_with("root") {
                server_block.push(http_line);
            }
        }

        return Some(result);
    }
    return None;
}

fn get_apache_urls() -> Option<HashMap<u16, Vec<Url>>> {
    let mut result: HashMap<u16, Vec<Url>> = HashMap::new();
    let mut server_port: u16 = 0;

    let config_dir = PathBuf::from("/etc/apache2/sites-enabled/");
    match read_dir(config_dir) {
        Ok(entries) => {
            for entry in entries {
                let path = entry.unwrap().path();
                if path.is_file() {
                    if let Ok(file) = File::open(&path) {
                        let reader = BufReader::new(file);
                        for line in reader.lines() {
                            if let Ok(line) = line {
                                if line.is_empty() {
                                    continue;
                                }
                                let pure_line = line.trim();
                                if pure_line.starts_with('#') {
                                    continue;
                                }
                                if pure_line.starts_with("<VirtualHost") {
                                    let port = pure_line.split(':').last().unwrap().trim_end_matches('>');
                                    match port.parse::<u16>() {
                                        Ok(port) => server_port = port,
                                        Err(_) => {}
                                    }
                                }
                                if pure_line.starts_with("DocumentRoot") {
                                    if server_port == 0 {
                                        continue;
                                    }
                                    let root_path_str = pure_line.split_whitespace().nth(1).unwrap();
                                    let root_path = PathBuf::from(root_path_str);
                                    if !root_path.is_absolute() {
                                        server_port = 0;
                                        continue;
                                    }
                                    let urls = get_urls("/", &root_path);
                                    result.insert(server_port, urls);
                                    server_port = 0;
                                }
                            }
                        }
                        return Some(result);
                    }
                }
            }
        }
        Err(_) => {}
    }
    return None;
}

fn get_tomcat_urls(catalina_base: &PathBuf) -> Option<HashMap<u16, Vec<Url>>> {
    let mut result: HashMap<u16, Vec<Url>> = HashMap::new();
    let mut server_port: u16 = 0;
    let xml_path = catalina_base.join("conf").join("server.xml");
    match File::open(xml_path) {
        Ok(file) => {
            let reader = BufReader::new(file);
            let parser = EventReader::new(reader);
            for event in parser {
                match event {
                    Ok(XmlEvent::StartElement { name, attributes, .. }) => {
                        if name.local_name == "Connector" {
                            let mut connector_port: u16 = 0;
                            let mut is_http: bool = false;
                            for attr in attributes {
                                if attr.name.local_name == "port" {
                                    let port_string = attr.value.to_owned();
                                    match port_string.parse::<u16>() {
                                        Ok(port) => connector_port = port,
                                        Err(_) => {}
                                    }
                                }
                                if attr.name.local_name == "protocol" {
                                    let protocol_string = attr.value.to_owned();
                                    if protocol_string.contains("HTTP") {
                                        is_http = true;
                                    }
                                }
                            }
                            if is_http && connector_port != 0 {
                                server_port = connector_port;
                                break;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        Err(_) => {}
    }
    if server_port != 0 {
        let mut urls: Vec<Url> = Vec::new();
        let web_dir = catalina_base.join("webapps");
        let default_web_dir = web_dir.join("ROOT");
        if default_web_dir.exists() {
            urls.extend(get_urls_without_regex("/", &default_web_dir, r"(\\|/)(WEB-INF|META-INF)(\\|/)"));
        }
        urls.extend(get_urls_without_regex("/", &web_dir, r"(\\|/)(ROOT|WEB-INF|META-INF)(\\|/)"));
        result.insert(server_port, urls);
        return Some(result);
    }
    return None;
}

fn get_docker_urls() -> Option<HashMap<u16, Vec<Url>>> {
    let mut result: HashMap<u16, Vec<Url>> = HashMap::new();

    return match Command::new("docker").args(&["ps", "--format", "{{.ID}}\t{{.Ports}}"]).output() {
        Ok(output) => {
            if !output.status.success() {
                return None;
            }
            let output_str = String::from_utf8_lossy(&output.stdout);
            let current_exe_path = env::current_exe().unwrap();
            let target_exe_path = current_exe_path.with_file_name("web_gather");
            if !target_exe_path.exists() {
                return None;
            }
            // 遍历容器
            for line in output_str.lines() {
                if line.is_empty() {
                    continue;
                }
                let container_id = line.split_whitespace().nth(0).unwrap();
                let port_mappings = line.trim_start_matches(container_id).trim();
                if port_mappings.is_empty() {
                    continue;
                }
                let mut port_map = HashMap::<u16, u16>::new();
                let mapping_re = Regex::new(r"(?P<host_port>\d+)->(?P<private_port>\d+)/tcp").unwrap();
                for port_mapping in port_mappings.split(',') {
                    if let Some(captures) = mapping_re.captures(port_mapping) {
                        if let Ok(host_port) = captures.name("host_port").unwrap().as_str().parse::<u16>() {
                            if let Ok(private_port) = captures.name("private_port").unwrap().as_str().parse::<u16>() {
                                port_map.insert(private_port, host_port);
                            }
                        }
                    }
                }

                if port_map.is_empty() {
                    continue;
                }
                let container_services: ServiceList;
                match Command::new("docker").args(&["exec", container_id, "uname", "-ms"]).output() {
                    Ok(container_info_output) => {
                        if !container_info_output.status.success() {
                            continue;
                        }
                        let container_info_str = String::from_utf8_lossy(&container_info_output.stdout);
                        let container_info = container_info_str.trim();
                        if !container_info.eq("Linux x86_64") {
                            continue;
                        }

                        let local_exe_arg = target_exe_path.display().to_string();
                        let target_exe_arg = format!("{}:/tmp/web_gather", container_id);
                        match Command::new("docker").args(&["cp", &local_exe_arg, &target_exe_arg]).output() {
                            Ok(copy_output) => {
                                if !copy_output.status.success() {
                                    continue;
                                }
                                match Command::new("docker").args(&["exec", container_id, "/tmp/web_gather"]).output() {
                                    Ok(exec_output) => {
                                        if !exec_output.status.success() {
                                            continue;
                                        }
                                        let exec_output_str = String::from_utf8_lossy(&exec_output.stdout);
                                        let exec_output = exec_output_str.trim();
                                        match serde_json::from_str::<ServiceList>(exec_output) {
                                            Ok(service_list) => {
                                                container_services = service_list;
                                            }
                                            Err(_) => {
                                                continue;
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        continue;
                                    }
                                }
                            }
                            Err(_) => {
                                continue;
                            }
                        }
                    }
                    Err(_) => {
                        continue;
                    }
                }

                for service in container_services.services {
                    if port_map.contains_key(&service.port) {
                        result.insert(port_map[&service.port], service.urls);
                    }
                }
            }
            Some(result)
        }
        Err(_) => {
            None
        }
    };
}

fn get_weblogic_urls(domain_home: &PathBuf) -> Option<HashMap<u16, Vec<Url>>> {
    let mut result: HashMap<u16, Vec<Url>> = HashMap::new();

    let mut server_port_map: HashMap<String, u16> = HashMap::new();
    let mut server_ssl_port_map: HashMap<String, u16> = HashMap::new();
    let mut app_server_map: HashMap<String, String> = HashMap::new();
    let mut app_path_map: HashMap<String, String> = HashMap::new();

    let xml_path = domain_home.join("config").join("config.xml");
    match File::open(xml_path) {
        Ok(file) => {
            let mut in_server_block = false;
            let mut in_app_block = false;
            let mut in_ssl_block = false;
            let mut is_name_tag = false;
            let mut is_listen_port_tag = false;
            let mut is_enabled_tag = false;
            let mut is_target_tag = false;
            let mut is_source_path_tag = false;
            let mut server_name = String::new();
            let mut server_port: u16 = 7001;
            let mut server_ssl_port: u16 = 7002;
            let mut ssl_enable: bool = true;
            let mut app_name = String::new();
            let mut source_path = String::new();

            let reader = BufReader::new(file);
            let parser = EventReader::new(reader);

            for event in parser {
                match event {
                    Ok(XmlEvent::StartElement { name, .. }) => {
                        match name.local_name.as_str() {
                            "server" => {
                                in_server_block = true;

                                server_name.clear();
                                server_port = 7001;
                                ssl_enable = true;
                                server_ssl_port = 7002;
                            }
                            "app-deployment" => {
                                in_app_block = true;

                                server_name.clear();
                                app_name.clear();
                                source_path.clear();
                            }
                            "ssl" => {
                                in_ssl_block = true;
                            }
                            "name" => {
                                is_name_tag = true;
                            }
                            "listen-port" => {
                                is_listen_port_tag = true;
                            }
                            "enabled" => {
                                is_enabled_tag = true;
                            }
                            "target" => {
                                is_target_tag = true;
                            }
                            "source-path" => {
                                is_source_path_tag = true;
                            }
                            _ => {}
                        }
                    }
                    Ok(XmlEvent::EndElement { name, .. }) => {
                        match name.local_name.as_str() {
                            "server" => {
                                if !server_name.is_empty() {
                                    server_port_map.insert(server_name.clone(), server_port);
                                    if ssl_enable {
                                        server_ssl_port_map.insert(server_name.clone(), server_ssl_port);
                                    }
                                }

                                in_server_block = false;
                            }
                            "app-deployment" => {
                                if !app_name.is_empty() && !server_name.is_empty() && !source_path.is_empty() {
                                    app_server_map.insert(app_name.clone(), server_name.clone());
                                    app_path_map.insert(app_name.clone(), source_path.clone());
                                }

                                in_app_block = false;
                            }
                            "ssl" => {
                                in_ssl_block = false;
                            }
                            "name" => {
                                is_name_tag = false;
                            }
                            "listen-port" => {
                                is_listen_port_tag = false;
                            }
                            "enabled" => {
                                is_enabled_tag = false;
                            }
                            "target" => {
                                is_target_tag = false;
                            }
                            "source-path" => {
                                is_source_path_tag = false;
                            }
                            _ => {}
                        }
                    }
                    Ok(XmlEvent::Characters(s)) => {
                        if is_name_tag {
                            if in_server_block {
                                server_name = s;
                            } else if in_app_block {
                                app_name = s;
                            }
                        } else if is_listen_port_tag {
                            if in_server_block {
                                match s.parse::<u16>() {
                                    Ok(port) => {
                                        if in_ssl_block {
                                            server_ssl_port = port;
                                        } else {
                                            server_port = port;
                                        }
                                    }
                                    Err(_) => {}
                                }
                            }
                        } else if is_enabled_tag {
                            if in_ssl_block {
                                match s.as_str() {
                                    "false" => {
                                        ssl_enable = false;
                                    }
                                    _ => {}
                                }
                            }
                        } else if is_target_tag {
                            if in_app_block {
                                server_name = s;
                            }
                        } else if is_source_path_tag {
                            if in_app_block {
                                source_path = s;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        Err(_) => {
            return None;
        }
    }

    for (app_name, server_name) in app_server_map.iter() {
        let mut ports: Vec<u16> = Vec::new();
        if let Some(server_port) = server_port_map.get(server_name) {
            ports.push(server_port.clone());
        }
        if let Some(server_ssl_port) = server_ssl_port_map.get(server_name) {
            ports.push(server_ssl_port.clone());
        }
        if ports.is_empty() {
            continue;
        }
        let mut urls: Vec<Url> = Vec::new();
        if let Some(source_path) = app_path_map.get(app_name) {
            let package_path = domain_home.join(source_path);
            let pathname = format!("/{}", package_path.file_name().unwrap().to_str().unwrap());
            let url = Url {
                pathname,
                checksum: calculate_checksum(&package_path),
            };
            urls.push(url);
        }
        let root_dir = domain_home.join("servers").join(server_name).join("tmp").join("_WL_user").join(app_name);
        match read_dir(&root_dir) {
            Ok(entries) => {
                for entry in entries {
                    let parent_path = entry.unwrap().path();
                    if parent_path.is_dir() {
                        match read_dir(&parent_path) {
                            Ok(sub_entries) => {
                                for sub_entry in sub_entries {
                                    let path = sub_entry.unwrap().path();
                                    if path.is_dir() {
                                        urls.extend(get_urls_without_regex("/", &path, r"(\\|/)(WEB-INF|META-INF)(\\|/)"));
                                    }
                                }
                            }
                            Err(_) => {}
                        }
                    }
                }
            }
            Err(_) => {}
        }

        for port in ports {
            result.insert(port, urls.clone());
        }
    }

    return Some(result);
}

fn get_process_detail(process: &Process, process_type: &ProcessType) -> Option<HashMap<u16, Vec<Url>>> {
    match process_type {
        ProcessType::Nginx => {
            // return None;
            let work_dir = process.cwd();
            let nginx_conf_path: PathBuf;
            if cfg!(target_os = "linux") {
                nginx_conf_path = PathBuf::from("/etc/nginx/nginx.conf");
            } else if cfg!(target_os = "windows") {
                nginx_conf_path = work_dir.join("conf/nginx.conf");
            } else {
                return None;
            }
            return get_nginx_urls(&nginx_conf_path, work_dir);
        }
        ProcessType::Apache2 => {
            // return None;
            return if cfg!(target_os = "linux") {
                get_apache_urls()
            } else {
                None
            };
        }
        ProcessType::Tomcat => {
            // return None;
            return if let Some(base_arg) = process.cmd().iter().find(|arg| arg.contains("catalina.base")) {
                let catalina_base = PathBuf::from(base_arg.trim_start_matches("-Dcatalina.base="));
                if !catalina_base.is_absolute() {
                    return None;
                }
                get_tomcat_urls(&catalina_base)
            } else {
                None
            };
        }
        ProcessType::WebLogic => {
            // return None;
            if let Some(home_arg) = process.environ().iter().find(|arg| arg.starts_with("DOMAIN_HOME=")) {
                let domain_home = PathBuf::from(home_arg.trim_start_matches("DOMAIN_HOME="));
                let file_to_analyze = domain_home.display().to_string();
                let mut analyzed_files = ANALYZED_FILES.lock().unwrap();
                if !analyzed_files.contains(&file_to_analyze) {
                    analyzed_files.insert(file_to_analyze);
                    if domain_home.exists() {
                        return get_weblogic_urls(&domain_home);
                    }
                }
            }
            return None;
        }
        ProcessType::Docker => {
            // return None;
            return get_docker_urls();
        }
        _ => {}
    }
    return None;
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // println!("---- START ----");

    let mut unique_ports = HashSet::new();
    let mut non_web_pids = HashSet::new();
    let mut port_pid_map: HashMap<u16, u32> = HashMap::new();
    let mut web_processes: HashMap<u32, &Process> = HashMap::new();
    let mut process_types: HashMap<u32, ProcessType> = HashMap::new();
    let mut web_port_urls: HashMap<u16, Vec<Url>> = HashMap::new();
    let show_related_ports = true;

    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let sockets_info = get_sockets_info(af_flags, proto_flags)?;

    let mut sys = System::new_all();
    sys.refresh_all();

    let mut result = ServiceList { services: vec![] };

    // 遍历开放端口
    for si in sockets_info {
        match si.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp_si) => {
                // 处于监听状态的TCP端口
                if tcp_si.state != TcpState::Listen {
                    continue;
                }
                let port = tcp_si.local_port;
                if !unique_ports.insert(port) {
                    continue;
                }
                // 不考虑端口共享的情况
                if si.associated_pids.is_empty() {
                    continue;
                }
                let pid = si.associated_pids[0];
                if non_web_pids.contains(&pid) {
                    continue;
                }
                match web_processes.get(&pid) {
                    Some(_) => {
                        port_pid_map.insert(port, pid);
                    }
                    None => {
                        let process_id = Pid::from(pid as usize);
                        if let Some(process) = sys.process(process_id) {
                            let command = process.cmd().join(" ");
                            let process_type = check_process_type(command);
                            if process_type != ProcessType::Unknown {
                                web_processes.insert(pid, process);
                                process_types.insert(pid, process_type);
                                port_pid_map.insert(port, pid);
                            } else {
                                non_web_pids.insert(pid);
                            }
                        } else {
                            non_web_pids.insert(pid);
                        }
                    }
                }
            }
            // ProtocolSocketInfo::Udp(udp_si) => {
            ProtocolSocketInfo::Udp(_) => {}
        }
    }

    // 遍历web进程
    for (key, value) in web_processes.iter() {
        if let Some(process_type) = process_types.get(key) {
            if let Some(result) = get_process_detail(*value, process_type) {
                web_port_urls.extend(result);
            }
        }
    }

    // 拼接返回结果
    for (key, value) in port_pid_map.iter() {
        let urls = match web_port_urls.remove(key) {
            Some(v) => v,
            None => {
                if show_related_ports {
                    Vec::new()
                } else {
                    continue;
                }
            }
        };
        if urls.len() == 0 {
            continue;
        }
        let process = match web_processes.get(value) {
            Some(v) => *v,
            None => continue,
        };
        let process_type = match process_types.get(value) {
            Some(v) => v,
            None => continue,
        };
        let port = *key;
        let pid = *value;
        let command = process.cmd().join(" ");

        result.services.push(Service {
            port,
            pid,
            service_type: process_type.to_string(),
            command,
            urls,
        });
    }

    result.services.sort_by(|a, b| a.port.cmp(&b.port));
    let result_str = serde_json::to_string(&result).unwrap();
    println!("{result_str}");

    // println!("---- END ----");
    Ok(())
}