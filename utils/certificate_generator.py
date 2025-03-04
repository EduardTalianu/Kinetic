#!/usr/bin/env python3
"""
Certificate Generator for Kinetic Compliance Matrix
Generates a self-signed certificate and private key for HTTPS connections.
"""

import os
import sys
import datetime
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_certificate(output_dir, hostname, ip_address, days_valid=365, 
                         org_name="KCM Testing", country="US", state="CA", locality="San Francisco"):
    """
    Generate a self-signed certificate and private key for HTTPS.
    
    Args:
        output_dir: Directory to save certificate files
        hostname: Server hostname
        ip_address: Server IP address (string format)
        days_valid: Certificate validity period in days
        org_name: Organization name for the certificate
        country: Country code
        state: State or province
        locality: City or locality
        
    Returns:
        tuple: (cert_path, key_path) paths to generated files
    """
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate our key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Various details about who we are
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])
    
    # Certificate validity period
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=days_valid)
    )
    
    # Add Subject Alternative Names (SANs) for hostname and IP
    san_list = []
    if hostname:
        san_list.append(x509.DNSName(hostname))
    if ip_address:
        # Convert string to IP address object
        ip_obj = ipaddress.ip_address(ip_address)
        san_list.append(x509.IPAddress(ip_obj))
    
    if san_list:
        cert = cert.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )
    
    # Add Basic Constraints extension
    cert = cert.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    
    # Sign the certificate with our private key
    cert = cert.sign(key, hashes.SHA256())
    
    # Write the certificate and private key to files
    cert_path = os.path.join(output_dir, "server.crt")
    key_path = os.path.join(output_dir, "server.key")
    
    # Write the certificate out to disk
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    # Write the private key out to disk
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    return cert_path, key_path

def read_certificate_info(cert_path):
    """
    Read information from an existing certificate
    
    Args:
        cert_path: Path to the certificate file
        
    Returns:
        dict: Certificate information
    """
    if not os.path.exists(cert_path):
        return {"error": "Certificate file not found"}
    
    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()
            
        cert = x509.load_pem_x509_certificate(cert_data)
        
        # Extract subject info
        subject = cert.subject
        subject_dict = {}
        for attr in subject:
            oid_name = attr.oid._name
            subject_dict[oid_name] = attr.value
        
        # Extract SAN extensions
        san_names = []
        san_ips = []
        try:
            ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in ext.value:
                if isinstance(name, x509.DNSName):
                    san_names.append(name.value)
                elif isinstance(name, x509.IPAddress):
                    san_ips.append(str(name.value))
        except x509.extensions.ExtensionNotFound:
            pass
        
        # Extract validity period
        not_valid_before = cert.not_valid_before
        not_valid_after = cert.not_valid_after
        
        # Calculate days remaining
        days_remaining = (not_valid_after - datetime.datetime.utcnow()).days
        
        return {
            "subject": subject_dict,
            "dns_names": san_names,
            "ip_addresses": san_ips,
            "issuer": {attr.oid._name: attr.value for attr in cert.issuer},
            "not_valid_before": not_valid_before.strftime("%Y-%m-%d %H:%M:%S"),
            "not_valid_after": not_valid_after.strftime("%Y-%m-%d %H:%M:%S"),
            "days_remaining": days_remaining
        }
        
    except Exception as e:
        return {"error": f"Failed to read certificate: {str(e)}"}