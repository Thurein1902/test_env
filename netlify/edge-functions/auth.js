// netlify/edge-functions/auth.js
import { getStore } from "https://deno.land/x/netlify@v0.7.2/mod.ts";

export default async (request, context) => {
  const url = new URL(request.url);
  const store = getStore("passwords");
  
  // Get passwords from database with defaults
  let loginPassword, adminPassword;
  try {
    loginPassword = await store.get("login_password") || "Q9wz3";
    adminPassword = await store.get("admin_password") || "increase123";
  } catch (error) {
    // Fallback defaults if database fails
    loginPassword = "Q9wz3";
    adminPassword = "increase123";
  }
  
  // Handle admin password change endpoint
  if (request.method === 'POST' && url.pathname === '/api/admin/change-password') {
    try {
      const { adminPassword: inputAdmin, oldPassword, newPassword } = await request.json();
      
      // Verify admin password
      if (inputAdmin !== adminPassword) {
        return new Response(
          JSON.stringify({ success: false, message: '管理者パスワードが間違っています。' }),
          { 
            status: 401,
            headers: { 'Content-Type': 'application/json' }
          }
        );
      }
      
      // Verify current login password
      if (oldPassword !== loginPassword) {
        return new Response(
          JSON.stringify({ success: false, message: '現在のパスワードが間違っています。' }),
          { 
            status: 401,
            headers: { 'Content-Type': 'application/json' }
          }
        );
      }
      
      // Update password in database
      await store.set("login_password", newPassword);
      
      return new Response(
        JSON.stringify({ success: true, message: 'パスワードが正常に更新されました！' }),
        { 
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        }
      );
      
    } catch (error) {
      return new Response(
        JSON.stringify({ success: false, message: 'サーバエラーになりました。管理者に連絡してください。' }),
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
        JSON.stringify({ success: false, message: 'サーバエラーになりました。管理者に連絡してください。' }),
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

// Validate session token (in production, store in database)
async function validateToken(token) {
  // Simple validation - in production, check against database
  return token && token.length === 64;
}

// Helper function to get cookie value
function getCookieValue(cookieString, name) {
  if (!cookieString) return null;
  const match = cookieString.match(new RegExp('(^| )' + name + '=([^;]+)'));
  return match ? match[2] : null;
}