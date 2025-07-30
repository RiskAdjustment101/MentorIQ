import { LandingLayout } from './components/LandingLayout';
import { RegistrationPage } from './components/registration/RegistrationPage';
import './index.css';

function App() {
  // Simple routing based on URL path
  const path = window.location.pathname;
  
  const renderPage = () => {
    switch (path) {
      case '/register':
        return <RegistrationPage />;
      default:
        return <LandingLayout />;
    }
  };

  return (
    <div className="App">
      {renderPage()}
    </div>
  );
}

export default App;