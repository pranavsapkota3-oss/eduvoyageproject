import Navbar from '../components/Navbar';
import Hero from '../components/Hero';
import WhyChoose from '../components/WhyChoose';
import Destinations from '../components/Destinations';
import Universities from '../components/Universities';
import Footer from '../components/Footer';

export default function Home() {
  return (
    <>
      <Navbar />
      <Hero />
      <WhyChoose />
      <Destinations />
      <Universities />
      <Footer />
    </>
  );
}
