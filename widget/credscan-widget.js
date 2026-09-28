document.addEventListener("DOMContentLoaded", () => {
    const dropzone = document.createElement('div');
    dropzone.style.cssText = `
        border: 2px dashed #444; 
        background: #111; 
        color: #fff; 
        padding: 40px; 
        text-align: center; 
        transition: all 0.3s ease;
    `;
    dropzone.innerHTML = `<h3>CredScan Validator</h3><p>Drag PDF here</p><div id="result"></div>`;
    document.body.appendChild(dropzone);

    dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropzone.style.boxShadow = "0 0 15px #39ff14";
        dropzone.style.borderColor = "#39ff14";
    });

    dropzone.addEventListener('dragleave', () => {
        dropzone.style.boxShadow = "none";
        dropzone.style.borderColor = "#444";
    });

    dropzone.addEventListener('drop', async (e) => {
        e.preventDefault();
        dropzone.style.boxShadow = "none";
        const file = e.dataTransfer.files[0];
        
        if (file.type !== "application/pdf" || file.size > 5 * 1024 * 1024) {
            alert("File rejected: Must be a PDF under 5MB.");
            return;
        }

        const formData = new FormData();
        formData.append("file", file);
        
        document.getElementById('result').innerHTML = `<p>Scanning...</p>`;
        const res = await fetch("http://localhost:8000/api/verify", { method: "POST", body: formData });
        const data = await res.json();

        if (data.status === "Verified") {
            document.getElementById('result').innerHTML = `
                <h4 style="color:#39ff14;">✅ VERIFIED</h4>
                <p>${data.hash}</p>
                <p><strong>HR AI Summary:</strong> ${data.hr_summary}</p>
            `;
        } else {
            document.getElementById('result').innerHTML = `<h4 style="color:red;">❌ ${data.status.toUpperCase()}</h4><p>${data.reason}</p>`;
        }
    });
});