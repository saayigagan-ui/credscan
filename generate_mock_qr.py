import json, zlib, base64, qrcode

# The mock student data structured like a government credential
student_data = {
    "name": "Alice Hacker",
    "usn": "1BM20CS001",
    "cgpa": 9.4,
    "degree": "B.Tech Computer Science",
    "issuer": "VTU Board of Examinations",
    "verified": True
}

# Compress and encode exactly like the DigiLocker payload protocol
json_str = json.dumps(student_data)
compressed_bytes = zlib.compress(json_str.encode('utf-8'))
encoded_payload = base64.b64encode(compressed_bytes).decode('utf-8')

# Generate the physical QR Code image
qr = qrcode.make(encoded_payload)
qr.save("mock_digilocker_qr.png")
print("Saved mock_digilocker_qr.png! Open this on your phone to scan with your laptop camera.")