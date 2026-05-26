export default function Footer() {
  return (
    <footer className="footer">
      <div className="footer-container">
        <div className="footer-column">
          <h4>EduVoyage</h4>
          <ul>
            <li><a href="#about">About Us</a></li>
            <li><a href="#careers">Careers</a></li>
            <li><a href="#contact">Contact</a></li>
          </ul>
        </div>

        <div className="footer-column">
          <h4>Study Destinations</h4>
          <ul>
            <li><a href="#usa">USA</a></li>
            <li><a href="#canada">Canada</a></li>
            <li><a href="#australia">Australia</a></li>
          </ul>
        </div>

        <div className="footer-column">
          <h4>Contact Info</h4>
          <p>Email: info@eduvoyage.com</p>
          <p>Phone: +977 9862366792</p>
          <p>Location: kathmandu,Nepal</p>
        </div>
      </div>

      <div className="footer-bottom">
        <p>&copy; {new Date().getFullYear()} EduVoyage. All rights reserved.</p>
      </div>
    </footer>
  );
}
