use worker::*;
use crate::config::Config;

pub async fn doh(req_wireformat: &[u8]) -> Result<Vec<u8>> {
    let mut headers = Headers::new();
    headers.set("Accept", "application/dns-message")?;
    headers.set("Content-Type", "application/dns-message")?;

    let mut response = Fetch::Url(Url::parse("https://1.1.1.1/dns-query")?)
        .post_with_headers(req_wireformat, headers)?
        .send()
        .await?;

    Ok(response.bytes().await?)
}

pub async fn handle_dns_request(mut req: Request, ctx: RouteContext<Config>) -> Result<Response> {
    let body = req.bytes().await?;
    
    // Parse domain from DNS query
    if let Some((domain, qname_len)) = parse_domain_name(&body) {
        // Check KV for blocked domain
        if let Ok(kv) = ctx.kv("DNS_CUSTOM") {
            if let Ok(Some(_)) = kv.get(&domain).text().await {
                // Domain is blocked. Spoof response to point to bluehat358.biz.id
                // We do this by querying 1.1.1.1 for bluehat358.biz.id instead of the original domain
                // preserving the original QTYPE (A/AAAA) and Transaction ID.
                
                let target_domain = "bluehat358.biz.id";
                let new_qname = encode_domain_name(target_domain);
                
                // Construct new query: Header (12) + New QNAME + Tail (QTYPE/QCLASS)
                // Original QNAME ends at 12 + qname_len
                let tail_start = 12 + qname_len;
                if tail_start <= body.len() {
                    let mut new_query = Vec::new();
                    new_query.extend_from_slice(&body[0..12]); // Header
                    new_query.extend_from_slice(&new_qname);   // New QNAME
                    new_query.extend_from_slice(&body[tail_start..]); // Tail (QTYPE, QCLASS, etc)
                    
                    // Send spoofed query
                    let response_bytes = doh(&new_query).await?;
                    
                    let mut headers = Headers::new();
                    headers.set("Content-Type", "application/dns-message")?;
                    return Ok(Response::from_bytes(response_bytes)?.with_headers(headers));
                }
            }
        }
    }

    let response_bytes = doh(&body).await?;
    
    let mut headers = Headers::new();
    headers.set("Content-Type", "application/dns-message")?;
    
    Ok(Response::from_bytes(response_bytes)?.with_headers(headers))
}

fn parse_domain_name(data: &[u8]) -> Option<(String, usize)> {
    if data.len() < 12 { return None; }
    let mut pos = 12;
    let mut domain = String::new();
    let start_pos = pos;
    
    loop {
        if pos >= data.len() { return None; }
        let len = data[pos] as usize;
        if len == 0 { 
            pos += 1; 
            break; 
        } 
        if len & 0xC0 == 0xC0 { return None; } // Compression not supported
        
        pos += 1;
        if pos + len > data.len() { return None; }
        
        if !domain.is_empty() {
            domain.push('.');
        }
        
        let label = std::str::from_utf8(&data[pos..pos+len]).ok()?;
        domain.push_str(label);
        pos += len;
    }
    
    Some((domain, pos - start_pos))
}

fn encode_domain_name(domain: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for label in domain.split('.') {
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    bytes
}
