 // API Configuration - Replace with your actual API endpoints
        const API_BASE_URL = ' '; // Change this to your backend URL
        
        let currentUser = null;
        let authToken = null;

        // Check authentication on page load
        window.addEventListener('load', async () => {
            const token = localStorage.getItem('authToken');
            if (token) {
                authToken = token;
                await verifyToken();
            }
        });

        // Login form handler
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            await login();
        });

        async function login() {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            showLoading('loginLoading', true);
            hideMessage('errorMessage');
            
            try {
                const response = await fetch(`${API_BASE_URL}/auth/login`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });

                const data = await response.json();
                
                if (response.ok) {
                    authToken = data.token;
                    currentUser = data.user;
                    localStorage.setItem('authToken', authToken);
                    showStoragePage();
                    await loadFiles();
                    showNotification('Login successful!', 'success');
                } else {
                    showMessage('errorMessage', data.message || 'Invalid credentials');
                }
            } catch (error) {
                showMessage('errorMessage', 'Connection error. Please try again.');
                console.error('Login error:', error);
            } finally {
                showLoading('loginLoading', false);
            }
        }

        async function verifyToken() {
            try {
                const response = await fetch(`${API_BASE_URL}/auth/verify`, {
                    headers: { 'Authorization': `Bearer ${authToken}` }
                });

                if (response.ok) {
                    const data = await response.json();
                    currentUser = data.user;
                    showStoragePage();
                    await loadFiles();
                } else {
                    localStorage.removeItem('authToken');
                    authToken = null;
                }
            } catch (error) {
                console.error('Token verification error:', error);
                localStorage.removeItem('authToken');
                authToken = null;
            }
        }

        async function logout() {
            if (confirm('Are you sure you want to logout?')) {
                try {
                    await fetch(`${API_BASE_URL}/auth/logout`, {
                        method: 'POST',
                        headers: { 'Authorization': `Bearer ${authToken}` }
                    });
                } catch (error) {
                    console.error('Logout error:', error);
                }
                
                localStorage.removeItem('authToken');
                authToken = null;
                currentUser = null;
                showLoginPage();
                showNotification('Logged out successfully', 'success');
            }
        }

        async function loadFiles() {
            showLoading('filesLoading', true);
            
            try {
                const response = await fetch(`${API_BASE_URL}/files`, {
                    headers: { 'Authorization': `Bearer ${authToken}` }
                });

                if (response.ok) {
                    const files = await response.json();
                    renderFiles(files);
                } else {
                    showNotification('Failed to load files', 'error');
                }
            } catch (error) {
                console.error('Load files error:', error);
                showNotification('Connection error', 'error');
            } finally {
                showLoading('filesLoading', false);
            }
        }

        // File upload handlers
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        const searchBox = document.getElementById('searchBox');

        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });

        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('dragover');
        });

        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            handleFiles(Array.from(e.dataTransfer.files));
        });

        fileInput.addEventListener('change', (e) => {
            handleFiles(Array.from(e.target.files));
            fileInput.value = '';
        });

        searchBox.addEventListener('input', async (e) => {
            await loadFiles();
        });

        async function handleFiles(files) {
            if (files.length === 0) return;
            
            showLoading('uploadLoading', true);
            
            for (const file of files) {
                const formData = new FormData();
                formData.append('file', file);

                try {
                    const response = await fetch(`${API_BASE_URL}/files/upload`, {
                        method: 'POST',
                        headers: { 'Authorization': `Bearer ${authToken}` },
                        body: formData
                    });

                    if (!response.ok) {
                        throw new Error('Upload failed');
                    }
                } catch (error) {
                    console.error('Upload error:', error);
                    showNotification(`Failed to upload ${file.name}`, 'error');
                }
            }
            
            showLoading('uploadLoading', false);
            showNotification(`${files.length} file(s) uploaded successfully!`, 'success');
            await loadFiles();
        }

        async function downloadFile(fileId, fileName) {
            try {
                const response = await fetch(`${API_BASE_URL}/files/${fileId}/download`, {
                    headers: { 'Authorization': `Bearer ${authToken}` }
                });

                if (response.ok) {
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const link = document.createElement('a');
                    link.href = url;
                    link.download = fileName;
                    link.click();
                    window.URL.revokeObjectURL(url);
                    showNotification('Download started!', 'success');
                } else {
                    showNotification('Download failed', 'error');
                }
            } catch (error) {
                console.error('Download error:', error);
                showNotification('Download failed', 'error');
            }
        }

        async function deleteFile(fileId) {
            if (!confirm('Are you sure you want to delete this file?')) return;
            
            try {
                const response = await fetch(`${API_BASE_URL}/files/${fileId}`, {
                    method: 'DELETE',
                    headers: { 'Authorization': `Bearer ${authToken}` }
                });

                if (response.ok) {
                    showNotification('File deleted successfully', 'success');
                    await loadFiles();
                } else {
                    showNotification('Failed to delete file', 'error');
                }
            } catch (error) {
                console.error('Delete error:', error);
                showNotification('Failed to delete file', 'error');
            }
        }

        function renderFiles(files) {
            const searchTerm = searchBox.value.toLowerCase();
            const filteredFiles = files.filter(file => 
                file.name.toLowerCase().includes(searchTerm)
            );

            document.getElementById('storageInfo').textContent = 
                `${files.length} file${files.length !== 1 ? 's' : ''} stored`;

            const fileGrid = document.getElementById('fileGrid');

            if (filteredFiles.length === 0) {
                fileGrid.innerHTML = `
                    <div class="empty-state">
                        <div class="empty-icon">${searchTerm ? '🔍' : '📁'}</div>
                        <h3>${searchTerm ? 'No files found' : 'No files yet'}</h3>
                        <p>${searchTerm ? 'Try a different search term' : 'Upload your first file to get started'}</p>
                    </div>
                `;
                return;
            }

            fileGrid.innerHTML = filteredFiles.map(file => `
                <div class="file-card">
                    <div class="file-icon">${getFileIcon(file.name, file.mime_type)}</div>
                    <div class="file-name">${file.name}</div>
                    <div class="file-size">${formatFileSize(file.size)}</div>
                    <div class="file-date">${formatDate(file.uploaded_at)}</div>
                    <div class="file-actions">
                        <button class="action-btn download-btn" onclick="downloadFile('${file.id}', '${file.name}')">
                            Download
                        </button>
                        <button class="action-btn delete-btn" onclick="deleteFile('${file.id}')">
                            Delete
                        </button>
                    </div>
                </div>
            `).join('');
        }

        function getFileIcon(filename, type) {
            const ext = filename.split('.').pop().toLowerCase();
            if (type && type.startsWith('image/')) return '🖼️';
            if (type && type.startsWith('video/')) return '🎥';
            if (type && type.startsWith('audio/')) return '🎵';
            if (ext === 'pdf') return '📄';
            if (['doc', 'docx'].includes(ext)) return '📝';
            if (['xls', 'xlsx'].includes(ext)) return '📊';
            if (['zip', 'rar', 'mq5', 'mq4', '7z'].includes(ext)) return '📦';
            if (['exe', 'apk', 'app'].includes(ext)) return '⚙️';
            if (['js', 'py', 'java', 'cpp', 'html', 'css'].includes(ext)) return '💻';
            return '📎';
        }

        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
        }

        function formatDate(dateString) {
            const date = new Date(dateString);
            return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
        }

        function showLoginPage() {
            document.getElementById('loginPage').style.display = 'flex';
            document.getElementById('storagePage').classList.remove('active');
            document.getElementById('username').value = '';
            document.getElementById('password').value = '';
        }

        function showStoragePage() {
            document.getElementById('loginPage').style.display = 'none';
            document.getElementById('storagePage').classList.add('active');
            if (currentUser) {
                document.getElementById('adminName').textContent = `👤 ${currentUser.username}`;
            }
        }

        function showLoading(id, show) {
            const element = document.getElementById(id);
            if (show) {
                element.classList.add('show');
            } else {
                element.classList.remove('show');
            }
        }

        function showMessage(id, message) {
            const element = document.getElementById(id);
            element.textContent = message;
            element.classList.add('show');
        }

        function hideMessage(id) {
            const element = document.getElementById(id);
            element.classList.remove('show');
        }

        function showNotification(message, type) {
            const notification = document.createElement('div');
            notification.className = `notification ${type}`;
            notification.textContent = message;
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.remove();
            }, 3000);
        }