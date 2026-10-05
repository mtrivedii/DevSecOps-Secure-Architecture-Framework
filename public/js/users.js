    // Check authentication and render appropriate content
    document.addEventListener('DOMContentLoaded', function() {
      // Get cookie helper function
      const getCookie = (name) => {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
        return null;
      };
      
      // Display hints only. The auth cookie is httpOnly and the server enforces access.
      const userEmail = localStorage.getItem('user_email');
      const userRole = localStorage.getItem('user_role');
      
      const container = document.getElementById('content-container');
      
      // If authenticated as admin, show users page
      if (userEmail && userRole && userRole.toLowerCase() === 'admin') {
        container.innerHTML = `
          <div class="container">
            <h1>👥 User Directory</h1>
            
            <div class="filter-container">
              <div class="search-filters">
                <div class="filter-group">
                  <label for="searchInput">Search:</label>
                  <input type="text" id="searchInput" placeholder="Filter by email..." class="search-input">
                </div>
                <div class="filter-group">
                  <label for="roleFilter">Role:</label>
                  <select id="roleFilter" class="role-select">
                    <option value="">All Roles</option>
                    <option value="admin">Admin</option>
                    <option value="user">User</option>
                  </select>
                </div>
              </div>
            </div>
            
            <div id="users" class="table-container">
              <div class="spinner"></div>
            </div>
            
            <div id="pagination" class="pagination hidden">
              <button id="prevPage" class="button pagination-button">&laquo; Previous</button>
              <span id="pageInfo" class="page-info">Page 1 of 1</span>
              <button id="nextPage" class="button pagination-button">Next &raquo;</button>
            </div>
            
            <div class="button-container">
              <a class="button" href="index.html">← Home</a>
              <button id="refreshButton" class="button">Refresh Data</button>
              <button id="logout-button" class="button warning">Logout</button>
            </div>
          </div>
        `;
        
        // Add logout functionality
        document.getElementById('logout-button').addEventListener('click', async function() {
          localStorage.removeItem('auth_token');
          localStorage.removeItem('user_role');
          localStorage.removeItem('user_email');
          try {
            await fetch('/api/logout', { method: 'POST', credentials: 'include' });
          } catch (e) {}
          window.location.href = '/';
        });
        
        // Initialize users data
        loadUsers();
      } 
      // If not authenticated or not admin, show unauthorized page
      else {
        container.innerHTML = `
          <div class="container">
            <h1>🔒 Unauthorized Access</h1>
            
            <div class="card">
              <h2>Authentication Required</h2>
              <p>You must be logged in with appropriate permissions to access this page.</p>
              <div class="button-container">
                <a href="/login.html" class="button">Login</a>
                <a href="/" class="button secondary">Return to Home</a>
              </div>
            </div>
          </div>
        `;
      }
    });
  
    // State management for user data and pagination
    const state = {
      users: [],
      filteredUsers: [],
      currentPage: 1,
      itemsPerPage: 10,
      loaded: false
    };
    
    // Load users from the API. The server checks the admin session cookie.
    async function loadUsers() {
      const usersDiv = document.getElementById('users');
      try {
        const response = await fetch('/api/users', { credentials: 'include' });
        if (response.status === 401 || response.status === 403) {
          usersDiv.textContent = 'You do not have permission to view users.';
          return;
        }
        if (!response.ok) {
          throw new Error(`Request failed with status ${response.status}`);
        }
        state.users = await response.json();
        state.loaded = true;
        state.currentPage = 1;
        wireUserControls();
        applyUserFilters();
      } catch (err) {
        usersDiv.textContent = 'Could not load users. Please try again.';
        console.error('Error loading users:', err.message);
      }
    }

    function wireUserControls() {
      if (state.wired) return;
      state.wired = true;
      document.getElementById('searchInput').addEventListener('input', () => {
        state.currentPage = 1;
        applyUserFilters();
      });
      document.getElementById('roleFilter').addEventListener('change', () => {
        state.currentPage = 1;
        applyUserFilters();
      });
      document.getElementById('prevPage').addEventListener('click', () => {
        if (state.currentPage > 1) { state.currentPage--; renderUsers(); }
      });
      document.getElementById('nextPage').addEventListener('click', () => {
        const pages = Math.max(1, Math.ceil(state.filteredUsers.length / state.itemsPerPage));
        if (state.currentPage < pages) { state.currentPage++; renderUsers(); }
      });
      document.getElementById('refreshButton').addEventListener('click', loadUsers);
    }

    function applyUserFilters() {
      const search = document.getElementById('searchInput').value.trim().toLowerCase();
      const role = document.getElementById('roleFilter').value.toLowerCase();
      state.filteredUsers = state.users.filter(u =>
        (!search || String(u.email || '').toLowerCase().includes(search)) &&
        (!role || String(u.role || '').toLowerCase() === role)
      );
      renderUsers();
    }

    // Build the table with textContent so user data is never parsed as HTML.
    function renderUsers() {
      const usersDiv = document.getElementById('users');
      const pagination = document.getElementById('pagination');
      usersDiv.textContent = '';

      if (state.filteredUsers.length === 0) {
        usersDiv.textContent = 'No users found.';
        pagination.style.display = 'none';
        return;
      }

      const pages = Math.max(1, Math.ceil(state.filteredUsers.length / state.itemsPerPage));
      state.currentPage = Math.min(state.currentPage, pages);
      const start = (state.currentPage - 1) * state.itemsPerPage;
      const rows = state.filteredUsers.slice(start, start + state.itemsPerPage);

      const table = document.createElement('table');
      const head = table.createTHead().insertRow();
      ['ID', 'Email', 'Role'].forEach(label => {
        const th = document.createElement('th');
        th.textContent = label;
        head.appendChild(th);
      });
      const body = table.createTBody();
      rows.forEach(u => {
        const tr = body.insertRow();
        [u.id, u.email, u.role].forEach(value => {
          tr.insertCell().textContent = value == null ? '' : String(value);
        });
      });
      usersDiv.appendChild(table);

      document.getElementById('pageInfo').textContent = `Page ${state.currentPage} of ${pages}`;
      pagination.style.display = pages <= 1 ? 'none' : '';
    }
