// netlify/edge-functions/auth.js

export default async (request, context) => {
  const url = new URL(request.url);
  
  // Fixed admin password (never changes)
  const ADMIN_PASSWORD = 'increase123';
  
  // Get login password from Netlify Blobs database
  async function getLoginPassword() {
    try {
      // Get from Netlify's built-in storage, default to 'Q9wz3' if not set
      const loginPassword = await context.storage.get('login_password') || 'Q9wz3';
      return loginPassword;
    } catch (error) {
      console.error('Storage error:', error);
      // Fallback to default if storage fails
      return 'Q9wz3';
    }
  }
  
  // Update login password in database
  async function updateLoginPassword(newPassword) {
    try {
      await context.storage.set('login_password', newPassword);
      return true;
    } catch (error) {
      console.error('Storage update error:', error);
      return false;
    }
  }
  
  // Handle admin password change endpoint
  if (request.method === 'POST' && url.pathname === '/api/admin/change-password') {
    try {
      const { adminPassword, oldPassword, newPassword } = await request.json();
      
      // Verify admin password (fixed, never changes)
      if (adminPassword !== ADMIN_PASSWORD) {
        return new Response(
          JSON.stringify({ success: false, message: '管理者パスワードが間違っています。' }),
          { 
            status: 401,
            headers: { 'Content-Type': 'application/json' }
          }
        );
      }
      
      // Verify current login password (from database)
      const currentLoginPassword = await getLoginPassword();
      if (oldPassword !== currentLoginPassword) {
        return new Response(
          JSON.stringify({ success: false, message: '現在のログインパスワードが間違っています。' }),
          { 
            status: 401,
            headers: { 'Content-Type': 'application/json' }
          }
        );
      }
      
      // Update login password in database
      const updateSuccess = await updateLoginPassword(newPassword);
      
      if (updateSuccess) {
        return new Response(
          JSON.stringify({ success: true, message: 'ログインパスワードが正常に更新されました！即座に有効になります。' }),
          { 
            status: 200,
            headers: { 'Content-Type': 'application/json' }
          }
        );
      } else {
        return new Response(
          JSON.stringify({ success: false, message: 'データベース更新に失敗しました。' }),
          { 
            status: 500,
            headers: { 'Content-Type': 'application/json' }
          }
        );
      }
      
    } catch (error) {
      return new Response(
        JSON.stringify({ success: false, message: 'サーバエラーが発生しました。' }),
        { 
          status: 500,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
  }
  
  // Handle login API endpoint
  if (request.method === 'POST' && url.pathname === '/api/auth') {
    try {
      const { password } = await request.json();
      const loginPassword = await getLoginPassword();
      
      if (password === loginPassword) {
        // Create a secure session token
        const sessionToken = await generateSessionToken();
        
        return new Response(
          JSON.stringify({ success: true, token: sessionToken }),
          {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
              'Set-Cookie': `auth_token=${sessionToken}; HttpOnly; Secure; SameSite=Strict; Max-Age=86400; Path=/`
            }
          }
        );
      } else {
        return new Response(
          JSON.stringify({ success: false, message: 'パスワードが間違っています。' }),
          { 
            status: 401,
            headers: { 'Content-Type': 'application/json' }
          }
        );
      }
    } catch (error) {
      return new Response(
        JSON.stringify({ success: false, message: 'サーバエラーが発生しました。' }),
        { 
          status: 500,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
  }
  
  // Check authentication for protected routes (exclude login page and admin page)
  if ((url.pathname === '/' || url.pathname === '/index.html' || url.pathname.startsWith('/protected/')) && 
      !url.pathname.includes('login.html') && !url.pathname.includes('admin.html')) {
    const authToken = getCookieValue(request.headers.get('cookie'), 'auth_token');
    
    if (!authToken || !await validateToken(authToken)) {
      // Redirect to login page
      return new Response(null, {
        status: 302,
        headers: { 'Location': '/login.html' }
      });
    }
  }
  
  // Continue to next handler for all other requests
  return context.next();
};

// Generate a secure session token
async function generateSessionToken() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

// Validate session token
async function validateToken(token) {
  return token && token.length === 64;
}

// Helper function to get cookie value
function getCookieValue(cookieString, name) {
  if (!cookieString) return null;
  const match = cookieString.match(new RegExp('(^| )' + name + '=([^;]+)'));
  return match ? match[2] : null;
}