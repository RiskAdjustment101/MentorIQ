# 🚀 MentorIQ Deployment Guide

## Git + Netlify Workflow (Recommended)

### **Step 1: Create GitHub Repository**

1. **Go to GitHub**: Visit [github.com](https://github.com) and sign in
2. **New Repository**: Click "New" or go to [github.com/new](https://github.com/new)
3. **Repository Settings**:
   - **Name**: `mentoriq-landing` (or your preferred name)
   - **Description**: `AI-enhanced FLL program discovery landing page`
   - **Visibility**: Public (for free Netlify)
   - **Initialize**: Leave unchecked (we already have code)

4. **Create Repository**: Click "Create repository"

### **Step 2: Push Code to GitHub**

```bash
# Add GitHub remote (replace with your username/repo)
git remote add origin https://github.com/YOUR_USERNAME/mentoriq-landing.git

# Push code to GitHub
git branch -M main
git push -u origin main
```

### **Step 3: Connect GitHub to Netlify**

1. **Go to Netlify**: Visit [app.netlify.com](https://app.netlify.com)
2. **New Site**: Click "New site from Git"
3. **Connect to GitHub**: Authorize Netlify to access your GitHub
4. **Select Repository**: Choose `mentoriq-landing`
5. **Build Settings**:
   - **Branch**: `main`
   - **Build command**: `npm run build`
   - **Publish directory**: `dist`
6. **Deploy Site**: Click "Deploy site"

### **Step 4: Automatic Deployments**

✅ **Every Git push** automatically triggers a new deployment
✅ **Pull requests** get preview deployments
✅ **Build logs** show detailed deployment status
✅ **Rollback capability** to previous deployments

## 🔄 Updating Your Site

### **Method 1: Git Workflow (Recommended)**

```bash
# Make changes to your code
# Then commit and push:

git add .
git commit -m "Update: description of changes"
git push origin main

# Netlify automatically deploys the changes!
```

### **Method 2: Direct Update (Existing Drag & Drop Site)**

1. **Go to your Netlify site dashboard**
2. **Drag new `dist` folder** to the "Deploys" section
3. **New deployment** automatically replaces the old one
4. **Same URL** continues working with updated content

## 🌐 Domain & Settings

### **Custom Domain Setup**

1. **Netlify Dashboard** → Your site → "Domain settings"
2. **Add custom domain**: `mentoriq.com` or your preferred domain
3. **DNS Setup**: Point your domain to Netlify
4. **HTTPS**: Automatically enabled with Let's Encrypt

### **Environment Variables**

```bash
# In Netlify Dashboard → Site Settings → Environment Variables
NODE_VERSION=18
VITE_API_URL=your-api-endpoint
```

### **Branch Deployments**

- **Production**: `main` branch → your main domain
- **Staging**: `develop` branch → preview URL
- **Feature branches**: Get individual preview URLs

## 📊 Netlify Features You Get

### **Automatic Optimization**
- ✅ **Asset optimization**: Images, CSS, JS automatically compressed
- ✅ **CDN**: Global content delivery network
- ✅ **HTTPS**: Free SSL certificates
- ✅ **Form handling**: Contact forms work out of the box

### **Developer Experience**
- ✅ **Build logs**: Detailed deployment information
- ✅ **Deploy previews**: Test changes before going live
- ✅ **Rollback**: One-click rollback to previous versions
- ✅ **Split testing**: A/B test different versions

### **Analytics & Monitoring**
- ✅ **Performance monitoring**: Core Web Vitals tracking
- ✅ **Deploy notifications**: Slack, email, webhooks
- ✅ **Custom headers**: Security and caching headers
- ✅ **Redirect rules**: URL redirects and rewrites

## 🛡️ Security & Performance

### **Included Security Headers**
```toml
# In netlify.toml
[[headers]]
  for = "/*"
  [headers.values]
    X-Frame-Options = "DENY"
    X-XSS-Protection = "1; mode=block"
    X-Content-Type-Options = "nosniff"
```

### **Asset Caching**
```toml
# Long-term caching for assets
[[headers]]
  for = "/assets/*"
  [headers.values]
    Cache-Control = "public, max-age=31536000, immutable"
```

## 🔧 Advanced Deployment Options

### **Build Plugins**

```toml
# In netlify.toml
[[plugins]]
  package = "@netlify/plugin-lighthouse"

[[plugins]]  
  package = "netlify-plugin-submit-sitemap"
```

### **Split Testing**

```toml
# A/B test different versions
[[redirects]]
  from = "/"
  to = "/version-a/:splat"
  status = 200
  conditions = {Cookie = "split-test=a"}
```

### **Custom Functions**

```bash
# For backend functionality
netlify/functions/
├── contact-form.js
├── ai-chat.js
└── analytics.js
```

## 🎯 Recommended Workflow

1. **Develop locally**: `npm run dev`
2. **Commit changes**: `git add . && git commit -m "description"`
3. **Push to GitHub**: `git push origin main`
4. **Auto-deploy**: Netlify builds and deploys automatically
5. **Monitor**: Check deployment in Netlify dashboard
6. **Test**: Verify changes on live site

## 🚨 Troubleshooting

### **Build Failures**
- Check build logs in Netlify dashboard
- Ensure `package.json` dependencies are correct
- Verify Node.js version compatibility

### **Routing Issues**
- Ensure `_redirects` file exists in `dist/`
- Check `netlify.toml` redirect rules
- Verify React Router configuration

### **Performance Issues**  
- Monitor Core Web Vitals in Netlify Analytics
- Optimize images and assets
- Review bundle size in build logs

---

**Your MentorIQ AI landing page is now ready for professional deployment with version control, automatic updates, and enterprise-grade hosting!** 🚀