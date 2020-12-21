use std::env;
use std::collections::HashMap;
use x509_parser::prelude::{parse_x509_certificate, parse_x509_pem};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        println!("Usage: {} [encode | decode] filename", &args[0]);
        std::process::exit(1);
    }

    let query = &args[1];
    let filename = &args[2];

    let mut entry: HashMap<String, String> = HashMap::new();

    if query == "encode" {
        let chain = std::fs::read_to_string(filename).expect("Could not load file");
        let mut is_new_entry = false;
        let mut is_first_entry = true;

        println!("[");

        for line in chain.lines() {
            if line.starts_with("-") {
                is_new_entry = !is_new_entry;

                if !is_new_entry {
                    if is_first_entry {
                        println!("\t{{");
                    } else {
                        println!("\t,{{");
                    }

                    println!("\t\t\"Issuer\": \"{}\",", entry["Issuer"]);
                    println!("\t\t\"Subject\": \"{}\",", entry["Subject"]);
                    println!("\t\t\"Not Valid Before\": \"{}\"", entry["Not Valid Before"]);
                    println!("\t}}");

                    is_new_entry = !is_new_entry;
                    is_first_entry = false;
                }
            } else {
                if line.starts_with("Issuer:") {
                    entry.insert("Issuer".to_string(), line.split("Issuer: ").nth(1).unwrap().to_string());
                } else if line.starts_with("Subject:") {
                    entry.insert("Subject".to_string(), line.split("Subject: ").nth(1).unwrap().to_string());
                } else if line.starts_with("Not Valid Before:") {
                    entry.insert("Not Valid Before".to_string(), line.split("Not Valid Before: ").nth(1).unwrap().to_string());
                }
            }
        }

        println!("]");
    } else if query == "decode" {
        let certs = std::fs::read_to_string(filename).expect("Could not load file");

        let split = certs.split("-----BEGIN CERTIFICATE-----");
        for s in split.skip(1) {
            let cert = format!("-----BEGIN CERTIFICATE-----{}", s);

            let tmpdata;
            let data: &[u8] = {
                let (_, _data) = parse_x509_pem(&cert.as_bytes()).expect("Could not decode the PEM file");
                tmpdata = _data;
                &tmpdata.contents
            };

            let (_, x509) = parse_x509_certificate(&data).expect("Could not decode DER data");

            println!("----------");
            println!("Issuer: {}", x509.issuer());
            println!("Subject: {}", x509.subject());
            println!("Not Valid Before: {}", x509.validity().not_before.to_rfc2822());
            // println!("Valid To: {}", x509.validity().not_after.to_rfc2822());
        }
        println!("----------");
    } else {
        println!("Usage: {} [encode | decode] filename", &args[0]);
        std::process::exit(1);
    }
}
