// Function to handle going back to tools.html
function goBack() {
    window.location.href = 'tools.html';
}

// Function to dynamically update form fields based on selected cipher mode
function updateFormFields() {
    const cipherMode = document.getElementById("cipherMode").value;
    const IVLabel = document.getElementById("IVLabel");
    const IVInput = document.getElementById("IV");
    const paddingLabel = document.getElementById("paddingLabel");
    const paddingSelect = document.getElementById("padding");
    const tagLenLabel = document.getElementById("tagLenLabel");
    const tagLenInput = document.getElementById("tagLen");

    // Show/hide IV input based on mode
    if (cipherMode === "CTR" || cipherMode === "OFB" || cipherMode === "CBC" || cipherMode === "GCM") {
        IVLabel.style.display = 'inline';
        IVInput.style.display = 'inline';
    } else {
        IVLabel.style.display = 'none';
        IVInput.style.display = 'none';
    }

    // Show/hide padding for CBC and ECB modes
    if (cipherMode === "CBC" || cipherMode === "ECB") {
        paddingLabel.style.display = 'inline';
        paddingSelect.style.display = 'inline';
    } else {
        paddingLabel.style.display = 'none';
        paddingSelect.style.display = 'none';
    }

    // Show/hide tag length for GCM mode
    if (cipherMode === "GCM") {
        tagLenLabel.style.display = 'inline';
        tagLenInput.style.display = 'inline';
    } else {
        tagLenLabel.style.display = 'none';
        tagLenInput.style.display = 'none';
    }
}

// Function to validate key size for AES (128, 192, 256 bits)
function validateKeySize(key, keySizeInBits) {
    const keySizeInBytes = key.length; // Length of key in characters (UTF-8 bytes)
    
    if (keySizeInBits === 128 && keySizeInBytes === 16) {
        return true;
    } else if (keySizeInBits === 192 && keySizeInBytes === 24) {
        return true;
    } else if (keySizeInBits === 256 && keySizeInBytes === 32) {
        return true;
    } else {
        // Show alert based on the key size mismatch
        alert(`Invalid key size. For ${keySizeInBits}-bit AES, the key must be ${keySizeInBits / 8} bytes.`);
        return false;
    }
}

// Function to encrypt data based on user input
async function encryptData() {
    const plainText = document.getElementById("plainText").value;
    const cipherMode = document.getElementById("cipherMode").value;
    const secretKey = document.getElementById("secretKey").value;
    const IV = document.getElementById("IV").value || null;
    const outputFormat = document.getElementById("outputFormat").value;
    const tagLen = parseInt(document.getElementById("tagLen").value, 10) || 128;
    const keySizeInBits = parseInt(document.getElementById("keySize").value, 10); // Get selected key size (128, 192, 256)

    if (!plainText || !secretKey || (IV === null && cipherMode !== "ECB")) {
        alert("Please provide all required inputs, including IV if needed.");
        return;
    }

    // Validate the key size based on the selected cipher mode
    if (!validateKeySize(secretKey, keySizeInBits)) {
        return;
    }

    const key = CryptoJS.enc.Utf8.parse(secretKey);
    const iv = IV ? CryptoJS.enc.Utf8.parse(IV) : null;

    let encryptedData;

    try {
        switch (cipherMode) {
            case "CTR":
                encryptedData = encryptCTR(plainText, key, iv, outputFormat);
                break;
            case "CBC":
                encryptedData = encryptCBC(plainText, key, iv, outputFormat);
                break;
            case "GCM":
                encryptedData = await encryptGCM(plainText, secretKey, IV, tagLen, outputFormat);
                break;
            case "ECB":
                encryptedData = encryptECB(plainText, key, outputFormat);
                break;
            case "OFB":
                encryptedData = encryptOFB(plainText, key, iv, outputFormat);
                break;
            default:
                alert("Unsupported cipher mode selected.");
                return;
        }

        document.getElementById("encryptedOutput").value = encryptedData;
    } catch (error) {
        console.error("Encryption error:", error);
        alert("An error occurred during encryption. Please check the console for details.");
    }
}

// CTR mode encryption
function encryptCTR(plainText, key, iv, format) {
    const encrypted = CryptoJS.AES.encrypt(plainText, key, {
        iv: iv,
        mode: CryptoJS.mode.CTR,
        padding: CryptoJS.pad.NoPadding,
    });

    return format === "hex"
        ? encrypted.ciphertext.toString(CryptoJS.enc.Hex)
        : encrypted.ciphertext.toString(CryptoJS.enc.Base64);
}

// CBC mode encryption
function encryptCBC(plainText, key, iv, format) {
    const encrypted = CryptoJS.AES.encrypt(plainText, key, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
    });

    return format === "hex"
        ? encrypted.ciphertext.toString(CryptoJS.enc.Hex)
        : encrypted.ciphertext.toString(CryptoJS.enc.Base64);
}

// ECB mode encryption
function encryptECB(plainText, key, format) {
    const encrypted = CryptoJS.AES.encrypt(plainText, key, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7,
    });

    return format === "hex"
        ? encrypted.ciphertext.toString(CryptoJS.enc.Hex)
        : encrypted.ciphertext.toString(CryptoJS.enc.Base64);
}

// Initialize form fields on page load
window.onload = function () {
    updateFormFields();
};
