import { BrowserRouter, Routes, Route, Navigate } from 'react-router';
import { DarkModeProvider } from './contexts/DarkModeContext';
import { I18nProvider } from './contexts/I18nContext';
import Layout from './components/layout/Layout';
import Discovery from './pages/Discovery';
import Prioritization from './pages/Prioritization';
import Monitoring from './pages/Monitoring';
import DetailedScan from './pages/DetailedScan';
import Compliance from './pages/Compliance';
import Drift from './pages/Drift';
import AILayer from './pages/AILayer';

export default function App() {
  return (
    <DarkModeProvider>
      <I18nProvider>
        <BrowserRouter>
          <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Navigate to="/monitoring" replace />} />
            <Route path="monitoring"     element={<Monitoring />}     />
            <Route path="discovery"      element={<Discovery />}      />
            <Route path="prioritization" element={<Prioritization />} />
            <Route path="scan"           element={<DetailedScan />}   />
            <Route path="compliance"     element={<Compliance />}     />
            <Route path="drift"          element={<Drift />}          />
            <Route path="ai"             element={<AILayer />}        />
          </Route>
          </Routes>
        </BrowserRouter>
      </I18nProvider>
    </DarkModeProvider>
  );
}
