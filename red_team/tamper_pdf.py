def tamper_document(input_path, output_path):
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())
    
    # Flip a single byte near the end of the file (bypassing superficial checks)
    data[-10] = data[-10] ^ 0xFF 
    
    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"Tampered PDF generated at: {output_path}")

tamper_document('PDF test file containing a valid signature.pdf', 'forged_marks.pdf')