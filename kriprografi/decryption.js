function goBack() {
    window.location.href = 'tools.html';
}

function updateFormFields() {
    const cipherMode = document.getElementById('cipherMode').value;
    const ivField = document.getElementById('IV');
    const ivLabel = document.getElementById('IVLabel');
    const tagLenField = document.getElementById('tagLen');
    const tagLenLabel = document.getElementById('tagLenLabel');

    if (cipherMode === 'CTR' || cipherMode === 'CBC' || cipherMode === 'GCM' || cipherMode === 'OFB') {
        ivField.style.display = 'block';
        ivLabel.style.display = 'block';
    } else {
        ivField.style.display = 'none';
        ivLabel.style.display = 'none';
    }

    if (cipherMode === 'GCM') {
        tagLenField.style.display = 'block';
        tagLenLabel.style.display = 'block';
    } else {
        tagLenField.style.display = 'none';
        tagLenLabel.style.display = 'none';
    }
}

function decryptData() {
    const cipherText = document.getElementById('cipherText').value;
    const cipherMode = document.getElementById('cipherMode').value;
    const keySize = parseInt(document.getElementById('keySize').value, 10);
    const secretKey = document.getElementById('secretKey').value;
    const iv = document.getElementById('IV').value;
    const outputFormat = document.getElementById('outputFormat').value;

    let decryptedOutput;

    try {
        const key = CryptoJS.enc.Utf8.parse(secretKey);
        const cipherParams = CryptoJS.lib.CipherParams.create({
            ciphertext: CryptoJS.enc.Base64.parse(cipherText)
        });

        let ivParams = iv ? CryptoJS.enc.Utf8.parse(iv) : undefined;

        const options = {
            mode: CryptoJS.mode[cipherMode],
            padding: CryptoJS.pad.Pkcs7,
            iv: ivParams
        };

        decryptedOutput = CryptoJS.AES.decrypt(cipherParams, key, options).toString(CryptoJS.enc.Utf8);

        if (outputFormat === 'base64') {
            decryptedOutput = CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(decryptedOutput));
        }

        document.getElementById('decryptedOutput').value = decryptedOutput;
    } catch (error) {
        document.getElementById('decryptedOutput').value = 'Decryption failed. Please check your inputs.';
    }
}
