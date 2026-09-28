from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pyhanko.sign.validation import async_validate_pdf_signature
from pyhanko.pdf_utils.reader import PdfFileReader
from typing import List
import io, hashlib, requests, json
import cv2, numpy as np
import zlib, base64

app = FastAPI(title="CredScan Engine")
app.add_middleware(
    CORSMiddleware, 
    allow_origins=["*"], 
    allow_credentials=True, 
    allow_methods=["*"], 
    allow_headers=["*"]
)

@app.post("/api/verify-bulk")
async def verify_bulk(files: List[UploadFile] = File(...)):
    results = []
    
    for file in files:
        file_bytes = await file.read()
        file_stream = io.BytesIO(file_bytes)
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        
        if file.content_type == "application/pdf":
            try:
                reader = PdfFileReader(file_stream)
                sig_fields = reader.embedded_signatures
                
                if not sig_fields:
                    results.append({"filename": file.filename, "status": "Failed", "reason": "No digital signature found."})
                    continue

                validation_status = await async_validate_pdf_signature(sig_fields[0])
                
                if validation_status.intact:
                    try:
                        cert_subject = validation_status.signer_cert.subject.native
                        signer_name = cert_subject.get('common_name', 'Verified Authority')
                    except AttributeError:
                        signer_name = "Verified Authority"
                    
                    ai_payload = {
                        "model": "qwen2.5-coder:1.5b",
                        "system": "You are an executive HR assistant. Output ONLY a single, professional sentence summarizing a candidate. Do not write any code, markdown, or JSON.",
                        "prompt": f"Write a 1-sentence HR summary for a candidate whose academic credentials were mathematically verified by {signer_name}.",
                        "stream": False
                    }
                    
                    try:
                        ai_res = requests.post("http://localhost:11434/api/generate", json=ai_payload, timeout=15).json()
                        hr_summary = ai_res.get("response", "AI summary unavailable.").strip()
                    except requests.exceptions.RequestException:
                        hr_summary = "Local Ollama service offline."

                    results.append({
                        "filename": file.filename,
                        "status": "Verified",
                        "hash": f"SHA-256: {file_hash[:10]}...",
                        "hr_summary": hr_summary
                    })
                else:
                    results.append({"filename": file.filename, "status": "Tampered", "reason": "Cryptographic hash mismatch."})
                    
            except Exception:
                results.append({"filename": file.filename, "status": "Tampered", "reason": "Document architecture corrupted or signature invalid."})
            finally:
                file_stream.close()
                
        elif file.content_type in ["image/jpeg", "image/png"]:
            try:
                nparr = np.frombuffer(file_bytes, np.uint8)
                image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                
                gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
                blurred = cv2.GaussianBlur(gray, (5, 5), 0)
                
                # Use native OpenCV instead of pyzbar
                detector = cv2.QRCodeDetector()
                raw_payload, bbox, straight_qrcode = detector.detectAndDecode(blurred)
                
                if not raw_payload:
                    results.append({"filename": file.filename, "status": "Failed", "reason": "No QR code localized."})
                    continue
                    
                try:
                    decompressed = zlib.decompress(base64.b64decode(raw_payload)).decode('utf-8')
                    student_json = json.loads(decompressed)
                    
                    # New AI Payload specifically for the QR JSON data
                    ai_payload = {
                        "model": "qwen2.5-coder:1.5b",
                        "system": "You are an executive HR assistant. Output ONLY a single sentence.",
                        "prompt": f"Write a 1-sentence HR summary for a candidate named {student_json.get('name', 'Unknown')} who holds a {student_json.get('degree', 'Degree')} with a CGPA of {student_json.get('cgpa', 'N/A')}.",
                        "stream": False
                    }
                    
                    try:
                        ai_res = requests.post("http://localhost:11434/api/generate", json=ai_payload, timeout=15).json()
                        hr_summary = ai_res.get("response", "AI summary unavailable.").strip()
                    except requests.exceptions.RequestException:
                        hr_summary = "Local Ollama service offline."

                    results.append({
                        "filename": file.filename, 
                        "status": "Verified", 
                        "data": student_json,
                        "hr_summary": hr_summary
                    })
                except Exception:
                    results.append({"filename": file.filename, "status": "Verified", "raw_payload": raw_payload[:50] + "..."})
            except Exception:
                results.append({"filename": file.filename, "status": "Failed", "reason": "Image processing error."})
            finally:
                file_stream.close()
        else:
            results.append({"filename": file.filename, "status": "Failed", "reason": "Unsupported MIME type."})
            file_stream.close()

    return {"batch_results": results}