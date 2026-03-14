// script.js

// API Configuration
const API_BASE_URL = 'https://cloud-storage-co.up.railway.app/api';

let currentUser = null;
let authToken   = null;
let allFiles    = []; // cache files locally so search doesn't re-fetch

// =============================
// INIT
// Wrap all DOM-dependent setup inside DOMContentLoaded so the script is
// safe to load without a `defer` attribute.
// =============================

document.addEventListener('DOMContentLoaded', () => {

  // ---- Element references (safe — DOM is guaranteed ready) ----
  const uploadArea = document.getElementById('uploadArea');
  const fileInput  = document.getElementById('fileInput');
  const searchBox  = document.getElementById('searchBox');

  // FIX #10 (corrected): Assign window._searchBox FIRST, before any async
  // calls that depend on it. Previously this was at the bottom of the
  // callback, so verifyToken() → loadFiles() → renderFiles() ran before
  // window._searchBox was set, causing renderFiles() to receive undefined
  // and skip filtering/counter updates on the initial page load.
  window._searchBox = searchBox;

  // ---- Upload drag-and-drop ----
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
    fileInput.value = ''; // reset so the same file can be re-selected
  });

  searchBox.addEventListener('input', () => {
    renderFiles(allFiles, searchBox);
  });

  // ---- Login form ----
  document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    await login();
  });

  // ---- Check auth on load ----
  (async () => {
    const token = localStorage.getItem('authToken');
    if (token) {
      authToken = token;
      await verifyToken(); // no arg needed — uses window._searchBox via loadFiles
    }
  })();
});

// =============================
// AUTH
// =============================

async function login() {
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;

  if (!username || !password) {
    showMessage('errorMessage', 'Please enter both username and password.');
    return;
  }

  showLoading('loginLoading', true);
  hideMessage('errorMessage');

  try {
    const response = await fetch(`${API_BASE_URL}/auth/login`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ username, password }),
    });

    const data = await response.json();

    if (response.ok) {
      authToken   = data.token;
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

// FIX: verifyToken takes no parameters. Previously called as verifyToken(searchBox)
// but the param was silently ignored. loadFiles() reaches window._searchBox directly.
async function verifyToken() {
  try {
    const response = await fetch(`${API_BASE_URL}/auth/verify`, {
      headers: { 'Authorization': `Bearer ${authToken}` },
    });

    if (response.ok) {
      const data = await response.json();
      currentUser = data.user;
      showStoragePage();
      await loadFiles();
    } else {
      clearSession();
    }
  } catch (error) {
    console.error('Token verification error:', error);
    clearSession();
  }
}

async function logout() {
  if (!confirm('Are you sure you want to logout?')) return;

  try {
    await fetch(`${API_BASE_URL}/auth/logout`, {
      method:  'POST',
      headers: { 'Authorization': `Bearer ${authToken}` },
    });
  } catch (error) {
    console.error('Logout error:', error);
  }

  clearSession();
  showLoginPage();
  showNotification('Logged out successfully', 'success');
}

// =============================
// Session management + 401 handler
// clearSession() is called whenever a 401/403 is received AND on logout.
// handleApiResponse() checks every authenticated response for an
// expired/invalid token and redirects to login automatically.
// =============================

function clearSession() {
  localStorage.removeItem('authToken');
  authToken   = null;
  currentUser = null;
  allFiles    = [];
}

/**
 * Call after every authenticated fetch.
 * Returns true  → session is still valid, continue.
 * Returns false → token expired/rejected; session cleared, redirected to login.
 */
function handleApiResponse(response) {
  if (response.status === 401 || response.status === 403) {
    clearSession();
    showLoginPage();
    showNotification('Session expired. Please log in again.', 'error');
    return false;
  }
  return true;
}

// =============================
// FILES
// =============================

async function loadFiles() {
  showLoading('filesLoading', true);

  try {
    const response = await fetch(`${API_BASE_URL}/files`, {
      headers: { 'Authorization': `Bearer ${authToken}` },
    });

    if (!handleApiResponse(response)) return;

    if (response.ok) {
      allFiles = await response.json();
      renderFiles(allFiles, window._searchBox);
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

// FIX: Upload validation + corrected spinner/notification order.
// - Client-side file size (50 MB) and type checks prevent wasted requests.
// - loadFiles() is awaited BEFORE hiding the spinner so the grid is never
//   stale when the spinner disappears.
// - Success notification is only shown when at least one upload succeeded.
// - loadFiles() is skipped entirely when nothing succeeded, avoiding an
//   unnecessary network round-trip.
const MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024; // 50 MB
const BLOCKED_EXTENSIONS  = ['exe', 'bat', 'sh', 'cmd', 'ps1', 'vbs'];

async function handleFiles(files) {
  if (files.length === 0) return;

  // Client-side validation
  const validFiles = [];
  for (const file of files) {
    const ext = file.name.split('.').pop().toLowerCase();
    if (BLOCKED_EXTENSIONS.includes(ext)) {
      showNotification(`"${file.name}" is not an allowed file type.`, 'error');
      continue;
    }
    if (file.size > MAX_FILE_SIZE_BYTES) {
      showNotification(`"${file.name}" exceeds the 50 MB size limit.`, 'error');
      continue;
    }
    validFiles.push(file);
  }

  if (validFiles.length === 0) return;

  showLoading('uploadLoading', true);

  let succeeded = 0;
  let failed    = 0;

  for (const file of validFiles) {
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch(`${API_BASE_URL}/files/upload`, {
        method:  'POST',
        headers: { 'Authorization': `Bearer ${authToken}` },
        body:    formData,
      });

      if (!handleApiResponse(response)) {
        showLoading('uploadLoading', false);
        return;
      }

      if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.message || 'Upload failed');
      }

      succeeded++;
    } catch (error) {
      failed++;
      console.error('Upload error:', error);
      showNotification(`Failed to upload "${file.name}": ${error.message}`, 'error');
    }
  }

  // Only refresh the list when at least one file was uploaded successfully.
  // Await loadFiles() BEFORE hiding the spinner so the grid is always up to
  // date by the time the loading indicator disappears.
  if (succeeded > 0) {
    await loadFiles();
    showNotification(
      `${succeeded} file${succeeded !== 1 ? 's' : ''} uploaded successfully!`,
      'success'
    );
  }

  showLoading('uploadLoading', false);
}

// =============================
// DOWNLOAD
// FIX: fetch the authenticated endpoint with redirect:'follow'. After the
// server issues its 302, response.url is the final signed URL (the browser
// exposes the redirected URL even for cross-origin fetches — it just blocks
// reading the response *body*). We navigate to that URL via a temporary
// anchor; no auth header is needed at that point because the signature is
// embedded in the URL by the server.
//
// Fallback: if response.url ends up being the original API URL (e.g. the
// server returned 200 with a JSON body instead of a redirect), we extract
// the URL from the JSON body instead.
// =============================

function downloadFile(fileId) {
  (async () => {
    try {
      const endpoint = `${API_BASE_URL}/files/${fileId}/download`;

      const response = await fetch(endpoint, {
        headers: { 'Authorization': `Bearer ${authToken}` },
        redirect: 'follow', // follow the 302 → signed R2 URL
      });

      if (!handleApiResponse(response)) return;

      if (!response.ok) {
        throw new Error(`Server returned ${response.status}`);
      }

      // Determine the URL to navigate to:
      // • If the server redirected us, response.url is the signed URL.
      // • If the server returned a JSON body with a `url` field, use that.
      let downloadUrl = response.url;

      // Detect when the redirect didn't happen (response.url === original endpoint)
      if (downloadUrl === endpoint || !downloadUrl) {
        try {
          const json = await response.json();
          downloadUrl = json.url || json.downloadUrl || '';
        } catch (_) {
          downloadUrl = '';
        }
      }

      if (!downloadUrl) {
        throw new Error('Could not obtain a download URL from the server.');
      }

      const link    = document.createElement('a');
      link.href     = downloadUrl;
      link.target   = '_blank';
      // Do NOT set link.download — the server's Content-Disposition header
      // already instructs the browser to download rather than navigate.
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      showNotification('Download started!', 'success');
    } catch (error) {
      console.error('Download error:', error);
      showNotification(`Download failed: ${error.message}`, 'error');
    }
  })();
}

async function deleteFile(fileId) {
  if (!confirm('Are you sure you want to delete this file?')) return;

  try {
    const response = await fetch(`${API_BASE_URL}/files/${fileId}`, {
      method:  'DELETE',
      headers: { 'Authorization': `Bearer ${authToken}` },
    });

    if (!handleApiResponse(response)) return;

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

// =============================
// RENDER
// FIX #2 & #7: Build file cards with the DOM API instead of innerHTML
// string interpolation, which allows XSS via filenames containing <script>
// tags or single-quotes that break onclick="..." handlers.
// FIX #6: Show "X of Y files" when a search filter is active.
// =============================

function renderFiles(files, searchBox) {
  const box        = searchBox || window._searchBox;
  const searchTerm = box ? box.value.toLowerCase() : '';

  const filteredFiles = files.filter(file =>
    (file.original_name || '').toLowerCase().includes(searchTerm)
  );

  // Update the file counter
  const infoEl = document.getElementById('storageInfo');
  if (infoEl) {
    if (searchTerm) {
      infoEl.textContent =
        `${filteredFiles.length} of ${files.length} file${files.length !== 1 ? 's' : ''}`;
    } else {
      infoEl.textContent =
        `${files.length} file${files.length !== 1 ? 's' : ''} stored`;
    }
  }

  const fileGrid = document.getElementById('fileGrid');
  if (!fileGrid) return;

  fileGrid.innerHTML = ''; // clear stale content

  if (filteredFiles.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    // Only the static strings go through innerHTML — no user data involved
    empty.innerHTML = `
      <div class="empty-icon">${searchTerm ? '🔍' : '📁'}</div>
      <h3>${searchTerm ? 'No files found' : 'No files yet'}</h3>
      <p>${searchTerm
        ? 'Try a different search term'
        : 'Upload your first file to get started'}</p>
    `;
    fileGrid.appendChild(empty);
    return;
  }

  filteredFiles.forEach(file => {
    const card = document.createElement('div');
    card.className = 'file-card';

    // Icon
    const iconEl       = document.createElement('div');
    iconEl.className   = 'file-icon';
    iconEl.textContent = getFileIcon(file.original_name, file.mime_type);

    // Name — textContent escapes everything, preventing XSS (FIX #2)
    const nameEl       = document.createElement('div');
    nameEl.className   = 'file-name';
    nameEl.textContent = file.original_name;
    nameEl.title       = file.original_name; // show full name on hover

    // Size
    const sizeEl       = document.createElement('div');
    sizeEl.className   = 'file-size';
    sizeEl.textContent = formatFileSize(file.size);

    // Date
    const dateEl       = document.createElement('div');
    dateEl.className   = 'file-date';
    dateEl.textContent = formatDate(file.uploaded_at);

    // Action buttons — addEventListener avoids all quote-escaping/XSS risks
    // that come with onclick="..." string interpolation (FIX #7)
    const actionsEl   = document.createElement('div');
    actionsEl.className = 'file-actions';

    const dlBtn           = document.createElement('button');
    dlBtn.className       = 'action-btn download-btn';
    dlBtn.textContent     = 'Download';
    dlBtn.addEventListener('click', () => downloadFile(file.id));

    const delBtn          = document.createElement('button');
    delBtn.className      = 'action-btn delete-btn';
    delBtn.textContent    = 'Delete';
    delBtn.addEventListener('click', () => deleteFile(file.id));

    actionsEl.appendChild(dlBtn);
    actionsEl.appendChild(delBtn);

    card.appendChild(iconEl);
    card.appendChild(nameEl);
    card.appendChild(sizeEl);
    card.appendChild(dateEl);
    card.appendChild(actionsEl);

    fileGrid.appendChild(card);
  });
}

// =============================
// HELPERS
// =============================

function getFileIcon(filename, type) {
  const ext = (filename || '').split('.').pop().toLowerCase();
  if (type && type.startsWith('image/')) return '🖼️';
  if (type && type.startsWith('video/')) return '🎥';
  if (type && type.startsWith('audio/')) return '🎵';
  if (ext === 'pdf')                                             return '📄';
  if (['doc', 'docx'].includes(ext))                            return '📝';
  if (['xls', 'xlsx'].includes(ext))                            return '📊';
  if (['zip', 'rar', 'mq5', 'mq4', '7z'].includes(ext))        return '📦';
  if (['exe', 'apk', 'app'].includes(ext))                      return '⚙️';
  if (['js', 'py', 'java', 'cpp', 'html', 'css'].includes(ext)) return '💻';
  return '📎';
}

// FIX #3: Guard against null / undefined / NaN bytes.
// FIX: Extended size units to TB and PB to avoid incorrect GB display for
// very large files.
function formatFileSize(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n < 0) return 'Unknown size';
  if (n === 0) return '0 Bytes';
  const k     = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i     = Math.min(Math.floor(Math.log(n) / Math.log(k)), sizes.length - 1);
  return Math.round((n / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

// FIX #4: Guard against null / undefined / invalid date strings.
function formatDate(dateString) {
  if (!dateString) return 'Unknown date';
  const date = new Date(dateString);
  if (isNaN(date.getTime())) return 'Invalid date';
  return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

// =============================
// UI STATE
// =============================

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

// FIX #8: Guard against missing element IDs so a typo doesn't throw an
// uncaught TypeError and break the rest of the page.
function showLoading(id, show) {
  const element = document.getElementById(id);
  if (!element) {
    console.warn(`showLoading: element #${id} not found`);
    return;
  }
  element.classList.toggle('show', show);
}

function showMessage(id, message) {
  const element = document.getElementById(id);
  if (!element) {
    console.warn(`showMessage: element #${id} not found`);
    return;
  }
  element.textContent = message; // textContent — safe against XSS
  element.classList.add('show');
}

function hideMessage(id) {
  const element = document.getElementById(id);
  if (!element) return;
  element.classList.remove('show');
}

function showNotification(message, type) {
  const notification       = document.createElement('div');
  notification.className   = `notification ${type}`;
  notification.textContent = message; // textContent — safe against XSS
  document.body.appendChild(notification);
  setTimeout(() => notification.remove(), 3000);
}
