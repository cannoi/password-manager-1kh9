let userId = null;

function showRegisterForm() {
  document.getElementById('login-form').style.display = 'none';
  document.getElementById('register-form').style.display = 'block';
}

function showLoginForm() {
  document.getElementById('register-form').style.display = 'none';
  document.getElementById('login-form').style.display = 'block';
}

async function register() {
  const username = document.getElementById('register-username').value;
  const password = document.getElementById('register-password').value;
  const email = document.getElementById('register-email').value;
  
  const response = await fetch('/register', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ username, password, email })
  });
  
  const data = await response.json();
  if (response.ok) {
    alert('Registration successful. Please scan the QR code with your authenticator app: ' + data.secret);
    showLoginForm();
  } else {
    alert('Registration failed: ' + data.error);
  }
}

async function login() {
  const username = document.getElementById('login-username').value;
  const password = document.getElementById('login-password').value;
  const token = document.getElementById('login-token').value;
  
  const response = await fetch('/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ username, password, token })
  });
  
  const data = await response.json();
  if (response.ok) {
    userId = data.userId;
    document.getElementById('login-form').style.display = 'none';
    document.getElementById('password-manager').style.display = 'block';
    loadPasswords();
  } else {
    alert('Login failed: ' + data.error);
  }
}

async function addPassword() {
  const service = document.getElementById('service').value;
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  const notes = document.getElementById('notes').value;
  
  const response = await fetch('/passwords', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ user_id: userId, service, username, password, notes })
  });
  
  const data = await response.json();
  if (response.ok) {
    alert('Password added successfully');
    loadPasswords();
  } else {
    alert('Failed to add password: ' + data.error);
  }
}

async function loadPasswords() {
  const response = await fetch(`/passwords/${userId}`);
  const passwords = await response.json();
  
  const passwordList = document.getElementById('passwords');
  passwordList.innerHTML = '';
  
  passwords.forEach(password => {
    const li = document.createElement('li');
    li.innerHTML = `
      <strong>Service:</strong> ${password.service}<br>
      <strong>Username:</strong> ${password.username}<br>
      <strong>Password:</strong> ${password.password}<br>
      <strong>Notes:</strong> ${password.notes}<br>
      <button onclick="editPassword(${password.id}, '${password.service}', '${password.username}', '${password.password}', '${password.notes}')">Edit</button>
      <button onclick="deletePassword(${password.id})">Delete</button>
    `;
    passwordList.appendChild(li);
  });
}

function editPassword(id, service, username, password, notes) {
  document.getElementById('service').value = service;
  document.getElementById('username').value = username;
  document.getElementById('password').value = password;
  document.getElementById('notes').value = notes;
  document.getElementById('password-form').innerHTML += `<button onclick="updatePassword(${id})">Update Password</button>`;
}

async function updatePassword(id) {
  const service = document.getElementById('service').value;
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  const notes = document.getElementById('notes').value;
  
  const response = await fetch(`/passwords/${id}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ service, username, password, notes })
  });
  
  const data = await response.json();
  if (response.ok) {
    alert('Password updated successfully');
    loadPasswords();
  } else {
    alert('Failed to update password: ' + data.error);
  }
}

async function deletePassword(id) {
  const response = await fetch(`/passwords/${id}`, {
    method: 'DELETE'
  });
  
  const data = await response.json();
  if (response.ok) {
    alert('Password deleted successfully');
    loadPasswords();
  } else {
    alert('Failed to delete password: ' + data.error);n  }
}

async function generatePassword() {
  const response = await fetch('/generate-password');
  const data = await response.json();
  document.getElementById('password').value = data.password;
}

async function checkPasswordStrength() {
  const password = document.getElementById('password').value;
  const response = await fetch('/check-password-strength', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ password })
  });
  const data = await response.json();
  alert(`Password strength: ${data.score}/4`);
}