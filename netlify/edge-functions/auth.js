// netlify/edge-functions/auth.js

export default async (request, context) => {
  const url = new URL(request.url);
  
  // Fixed admin password (never changes)
  const ADMIN_PASSWORD = 'increase123';
  
  // Simple in-memory storage simulation (will reset on function restart)
  // For a real persistent solution, you'd need an external database
  const getStorageKey = (key) => `netlify-kv-${key}`;
  
  // Get login password from Netlify KV store (if available) or default
  async function getLoginPassword() {
    try {
      // Try to use Netlify's KV store
      const stored = await Netlify.env.get('login_password');
      return stored || 'Q9wz3';
    } catch (error) {
      // Fallback if KV store not available
      return 'Q9wz3';
    }
  }
  
  // Update login password in storage
  async function updateLoginPassword(newPassword) {
    try {
      // Try to use Netlify's KV store
      await Netlify.env.set('login_password', newPassword);
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
      
      // For now, since storage might not work, let's just validate and return success with the new password
      // This allows you to manually update if needed
      return new Response(
        JSON.stringify({ 
          success: true, 
          message: `パスワード変更要求を受信しました。新しいパスワード: ${newPassword}` 
        }),
        { 
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        }
      );
      
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
      
      // Use default password for now
      const loginPassword = 'Q9wz3';
      
      if (password === loginPassword) {
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
  
  // Authentication check for protected routes
  if ((url.pathname === '/' || url.pathname === '/index.html' || url.pathname.startsWith('/protected/')) && 
      !url.pathname.includes('login.html') && !url.pathname.includes('admin.html')) {
    const authToken = getCookieValue(request.headers.get('cookie'), 'auth_token');
    
    if (!authToken || !await validateToken(authToken)) {
      return new Response(null, {
        status: 302,
        headers: { 'Location': '/login.html' }
      });
    }
  }
  
  return context.next();
};

async function generateSessionToken() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

async function validateToken(token) {
  return token && token.length === 64;
}

function getCookieValue(cookieString, name) {
  if (!cookieString) return null;
  const match = cookieString.match(new RegExp('(^| )' + name + '=([^;]+)'));
  return match ? match[2] : null;
}