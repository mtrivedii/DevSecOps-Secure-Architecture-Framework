document.addEventListener('DOMContentLoaded', function() {
  const fileInput = document.getElementById('file');
  const filenameDisplay = document.getElementById('filename-display');
  const fileDetails = document.getElementById('fileDetails');
  const fileSize = document.getElementById('fileSize');
  const fileType = document.getElementById('fileType');
  const uploadButton = document.getElementById('uploadButton');
  const uploadForm = document.getElementById('uploadForm');
  const uploadMessage = document.getElementById('uploadMessage');
  const progressContainer = document.getElementById('uploadProgress');
  const progressBar = document.getElementById('progressBar');
  const progressText = document.getElementById('progressText');

  // Authentication check removed

  // File selection handler
  fileInput.addEventListener('change', function() {
    if (this.files.length === 0) {
      filenameDisplay.textContent = 'No file selected';
      fileDetails.style.display = 'none';
      uploadButton.disabled = true;
      return;
    }

    const file = this.files[0];
    filenameDisplay.textContent = file.name;
    fileSize.textContent = formatFileSize(file.size);
    fileType.textContent = file.type || 'Unknown';
    fileDetails.style.display = 'block';

    // Validate file type and size
    const validExtensions = ['.pdf', '.doc', '.docx', '.txt', '.jpg', '.jpeg', '.png', '.gif', '.csv', '.json', '.xml'];
    const maxSize = 10 * 1024 * 1024; // 10MB

    const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
    const isValidType = validExtensions.includes(fileExtension);
    const isValidSize = file.size <= maxSize;

    // Also validate content type for security
    const validMimeTypes = [
      'application/pdf',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'text/plain',
      'image/jpeg',
      'image/png',
      'image/gif',
      'text/csv',
      'application/json',
      'application/xml',
      'text/xml'
    ];
    
    const isValidMimeType = !file.type || validMimeTypes.includes(file.type);

    if (!isValidType) {
      uploadMessage.textContent = 'Error: File type not allowed';
      uploadMessage.className = 'warning';
      uploadButton.disabled = true;
    } else if (!isValidMimeType) {
      uploadMessage.textContent = 'Error: File content type not allowed';
      uploadMessage.className = 'warning';
      uploadButton.disabled = true;
    } else if (!isValidSize) {
      uploadMessage.textContent = 'Error: File exceeds 10MB size limit';
      uploadMessage.className = 'warning';
      uploadButton.disabled = true;
    } else {
      uploadMessage.textContent = '';
      uploadButton.disabled = false;
    }
  });

  // Enhanced SAS token request
  async function getSasToken(filename, contentType) {
    try {
      // Important: Use your actual backend URL, not a relative path
      // This avoids CORS issues with AAD authentication
      const baseUrl = window.location.origin;
      const apiUrl = `${baseUrl}/api/getSasToken?blobName=${encodeURIComponent(filename)}` +
        (contentType ? `&contentType=${encodeURIComponent(contentType)}` : '');
      
      const response = await fetch(apiUrl, {
        method: 'GET',
        headers: {
          "Accept": "application/json",
          "Cache-Control": "no-cache, no-store, must-revalidate",
          "Pragma": "no-cache"
        },
        credentials: 'include' // Always include credentials
      });
      
      if (!response.ok) {
        // Authentication check removed
        
        let errorText = await response.text();
        try {
          const errorJson = JSON.parse(errorText);
          throw new Error(errorJson.error || errorJson.details || `Failed to get SAS token: ${response.status}`);
        } catch (parseError) {
          throw new Error(`Failed to get SAS token: ${errorText.substring(0, 100)}`);
        }
      }
      
      const data = await response.json();
      
      if (!data || !data.sasUrl) {
        throw new Error('Invalid SAS token response: missing sasUrl');
      }
      
      return data;
    } catch (error) {
      console.error('Error getting SAS token:', error);
      throw error;
    }
  }

  // Form submission handler with enhanced error handling
  uploadForm.addEventListener('submit', async function(e) {
    e.preventDefault();

    const file = fileInput.files[0];
    if (!file) return;

    // Show progress UI
    progressContainer.style.display = 'block';
    progressBar.style.width = '0%';
    progressText.textContent = '0%';
    uploadButton.disabled = true;
    uploadMessage.textContent = 'Requesting upload permission...';
    uploadMessage.className = '';

    try {
      // Request SAS token
      const data = await getSasToken(file.name, file.type);
      const sasUrl = data.sasUrl;
      
      uploadMessage.textContent = 'Uploading file...';

      // Upload with XMLHttpRequest for progress reporting
      const uploadPromise = new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        
        // Set up progress tracking
        xhr.upload.addEventListener('progress', function(e) {
          if (e.lengthComputable) {
            const percentComplete = Math.round((e.loaded / e.total) * 100);
            progressBar.style.width = percentComplete + '%';
            progressText.textContent = percentComplete + '%';
          }
        });

        // Set up completion handler
        xhr.onreadystatechange = function() {
          if (xhr.readyState === 4) {
            if (xhr.status >= 200 && xhr.status < 300) {
              resolve();
            } else {
              let errorMsg = 'Upload failed: Server returned status ' + xhr.status;
              if (xhr.statusText) errorMsg = 'Upload failed: ' + xhr.statusText;
              reject(new Error(errorMsg));
            }
          }
        };
        
        // Set up error handler
        xhr.onerror = function() {
          reject(new Error('Network error during upload'));
        };
        
        // Set up timeout handler
        xhr.timeout = 120000; // 2 minutes
        xhr.ontimeout = function() {
          reject(new Error('Upload timed out'));
        };

        // Start the upload
        xhr.open('PUT', sasUrl, true);
        xhr.setRequestHeader('x-ms-blob-type', 'BlockBlob');
        xhr.setRequestHeader('Content-Type', file.type || 'application/octet-stream');
        xhr.send(file);
      });

      // Wait for upload to complete
      await uploadPromise;
      
      // Ask the server to check the file's content now that it is stored
      uploadMessage.textContent = 'Checking file...';
      const verify = await fetch('/api/verifyUpload', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ blobName: data.storedName })
      });
      if (!verify.ok) {
        let reason = 'File check failed';
        try { reason = (await verify.json()).error || reason; } catch (e) { /* keep default */ }
        throw new Error('Upload rejected: ' + reason);
      }

      // Show success message
      uploadMessage.textContent = 'Upload successful!';
      uploadMessage.className = 'success';
      
      // Reset form after delay
      setTimeout(() => {
        uploadForm.reset();
        filenameDisplay.textContent = 'No file selected';
        fileDetails.style.display = 'none';
        progressContainer.style.display = 'none';
        progressBar.style.width = '0%';
        progressText.textContent = '0%';
        uploadButton.disabled = true;
      }, 2000);
    } catch (error) {
      // Handle errors
      console.error('Upload error:', error);
      progressContainer.style.display = 'none';
      uploadMessage.textContent = 'Upload error: ' + error.message;
      uploadMessage.className = 'warning';
      uploadButton.disabled = false;
    }
  });

  // Helper function to format file size
  function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }
});