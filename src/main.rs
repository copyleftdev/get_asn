use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::net::IpAddr;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Check if a domain name is provided
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <domain>", args[0]);
        return Ok(());
    }
    
    let domain = &args[1];

    // Resolve the domain to its IP address
    let ip = resolve_domain_to_ip(domain).await?;
    
    if ip.is_none() {
        println!("Could not resolve the domain: {}", domain);
        return Ok(());
    }

    let ip = ip.unwrap();
    
    // Query ASN information
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
    // No need to await here, just handle the result directly
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())?;

    let response = resolver.lookup_ip(domain).await?;

    // Get the first IP address from the response, if available
    Ok(response.iter().next())
}

fn query_asn_info(ip: &IpAddr) -> Result<String, Box<dyn Error>> {
    // Connect to whois.cymru.com on port 43
    let mut stream = TcpStream::connect("whois.cymru.com:43")?;

    // Send the IP query to the WHOIS server
    let query = format!(" -v {}\r\n", ip);
    stream.write_all(query.as_bytes())?;

    // Read the response from the server
    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    // Extract the result line, skipping the header line
    let asn_info: Vec<&str> = response
        .lines()
        .skip(1)
        .collect();

    // Join the lines into a single string
    Ok(asn_info.join("\n"))
}
