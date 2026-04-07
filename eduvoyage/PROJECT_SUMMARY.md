# EduVoyage - Responsive React Landing Page

## ✅ Project Complete

A fully responsive, professional landing page for a study-abroad platform built with React, Vite, and React Router.

---

## 📋 Features Implemented

### 1. **Navigation Bar (Sticky)**
- Logo with gradient styling
- Menu links: Home, Countries, Take Courses, Scholarship Finder, Services
- Auth buttons: Sign Up (primary gradient), Login (secondary outline)
- Dark blue gradient background with hover effects
- Fully responsive mobile menu

### 2. **Hero Section**
- Full-width background with gradient overlay
- Large heading: "Find Your Perfect Study Abroad Program"
- Descriptive subtitle about international education
- Semi-transparent search card with:
  - Dropdown for destination country
  - Dropdown for program type
  - Search button with gradient
- Mobile responsive design

### 3. **Why Choose EduVoyage Section**
- 3 feature cards in responsive grid:
  - End-to-End Support 🎓
  - Scholarship Opportunities 💰
  - University Partnerships 🌍
- Cards with shadows, rounded corners, and hover animations

### 4. **Top Study Destinations**
- Grid layout with 4 country cards:
  - Australia 🇦🇺
  - United States 🇺🇸
  - Canada 🇨🇦
  - United Kingdom 🇬🇧
- Hover scale animations
- "Learn More" buttons with outline styling

### 5. **Featured Universities**
- Horizontal scrolling row of university logos
- Placeholder cards for: Harvard, Oxford, MIT, Cambridge, Stanford, Toronto
- Interactive hover effects

### 6. **Footer**
- Dark background (#1f2937)
- 3-column layout:
  - EduVoyage (About Us, Careers, Contact)
  - Study Destinations (USA, Canada, Australia)
  - Contact Info (Email, Phone)
- Copyright text
- Responsive grid layout

### 7. **Authentication Pages**

#### Login Page
- Split layout (image on left, form on right)
- Email and password inputs
- Login button with gradient
- Link to sign up
- Responsive: stacks on mobile

#### Signup Page
- Split layout with animated gradient background
- Full name, email, password, confirm password inputs
- Form validation (password matching)
- Create Account button
- Link to login
- Mobile responsive

---

## 🗂️ Project Structure

```
src/
├── components/
│   ├── Navbar.jsx          (Sticky navigation bar)
│   ├── Hero.jsx            (Hero section with search)
│   ├── WhyChoose.jsx       (3 feature cards)
│   ├── Destinations.jsx    (Country cards grid)
│   ├── Universities.jsx    (University logos row)
│   └── Footer.jsx          (Footer with links)
├── pages/
│   ├── Home.jsx            (Main landing page)
│   ├── Login.jsx           (Login form page)
│   └── Signup.jsx          (Signup form page)
├── App.jsx                 (Router configuration)
├── main.jsx                (React entry point)
└── index.css               (Complete styling - 500+ lines)
```

---

## 🎨 Styling Highlights

### Colors
- Primary: #3b82f6 (Blue)
- Secondary: #2563eb (Dark Blue)
- Gradient: 135deg from #667eea to #764ba2
- Dark Backgrounds: #1f2937, #0f172a

### Typography
- Font: Segoe UI, Tahoma, Geneva, Verdana, sans-serif
- Responsive font sizes (48px → 24px on mobile)
- Smooth transitions and animations

### Effects
- Gradient backgrounds on hero and buttons
- Hover animations (scale, shadow, color changes)
- Smooth scrolling
- Backdrop blur effects
- Float animations on auth pages

---

## 📱 Responsive Design

### Breakpoints
- **Desktop**: Full layout with all elements
- **Tablet (768px)**: Stacked navbar, adjusted grid
- **Mobile (480px)**: Single column, hidden images on auth pages

### Mobile Features
- Touch-friendly button sizes
- Readable font sizes
- Full-width inputs
- Stacked sections

---

## 🚀 Running the Project

### Installation
```bash
cd eduvoyage
npm install
```

### Development
```bash
npm run dev
```
Server runs on `http://localhost:5176/` (or next available port)

### Build
```bash
npm run build
```

### Preview
```bash
npm run preview
```

---

## 📦 Dependencies

```json
{
  "react": "^19.2.0",
  "react-dom": "^19.2.0",
  "react-router-dom": "^6.20.0"
}
```

**No external UI libraries** - Pure CSS styling with semantic HTML

---

## ✨ Key Features

✅ Responsive design (mobile, tablet, desktop)
✅ React Router for seamless page navigation
✅ Form validation and state management
✅ Modern UI with gradients and animations
✅ Professional education website styling
✅ Accessibility-friendly semantic HTML
✅ Clean, maintainable code structure
✅ No Tailwind or Bootstrap - pure CSS
✅ Sticky navigation bar
✅ Interactive components with hover effects

---

## 🔗 Routes

| Path | Component | Description |
|------|-----------|-------------|
| `/` | Home | Landing page with all sections |
| `/login` | Login | User login form |
| `/signup` | Signup | User registration form |

---

## 📝 Notes

- All components are functional React components
- Uses hooks (useState) for form state management
- Pure CSS with no build dependencies for styles
- Fully semantic HTML structure
- Ready for backend integration
- Mobile-first responsive design approach

---

**Status**: ✅ Complete and Running
**Environment**: Vite + React 19 + React Router 6
