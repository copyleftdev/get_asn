use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::net::IpAddr;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <domain>", args[0]);
        return Ok(());
    }
    
    let domain = &args[1];

   
    let ip = resolve_domain_to_ip(domain).await?;
    
    if ip.is_none() {
        println!("Could not resolve the domain: {}", domain);
        return Ok(());
    }

    let ip = ip.unwrap();
    
   
    let asn_info = query_asn_info(&ip)?;
    
    if asn_info.is_empty() {
        println!("Could not retrieve ASN information for IP: {}", ip);
        return Ok(());
    }

    // Display ASN information
    println!("AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name");
    println!("{}", asn_info);

    Ok(())
}

async fn resolve_domain_to_ip(domain: &str) -> Result<Option<IpAddr>, Box<dyn Error>> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())?;

    let response = resolver.lookup_ip(domain).await?;

    Ok(response.iter().next())
}

fn query_asn_info(ip: &IpAddr) -> Result<String, Box<dyn Error>> {
  
    let mut stream = TcpStream::connect("whois.cymru.com:43")?;

    let query = format!(" -v {}\r\n", ip);
    stream.write_all(query.as_bytes())?;

  
    let mut response = String::new();
    stream.read_to_string(&mut response)?;

  
    let asn_info: Vec<&str> = response
        .lines()
        .skip(1)
        .collect();

    
    Ok(asn_info.join("\n"))
}
