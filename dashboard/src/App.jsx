import { Navigate, Route, Routes } from 'react-router-dom'
import { AuthGateProvider } from './components/AuthGate.jsx'
import Shell from './components/Shell.jsx'
import Login from './pages/Login.jsx'
import Verify from './pages/Verify.jsx'
import Overview from './pages/Overview.jsx'
import Alerts from './pages/Alerts.jsx'
import Tickets from './pages/Tickets.jsx'
import { IncidentList, IncidentDetail } from './pages/Incidents.jsx'
import Endpoints from './pages/Endpoints.jsx'
import { Events, Identity, Audit } from './pages/Lists.jsx'
import Rules from './pages/Rules.jsx'
import Backups from './pages/Backups.jsx'
import Terminal from './pages/Terminal.jsx'

const Protected = ({ children }) => (localStorage.getItem('edr_token') ? children : <Navigate to="/login" replace />)

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/verify/:id" element={<Verify />} />
      <Route path="/*" element={<Protected><AuthGateProvider><Shell /></AuthGateProvider></Protected>}>
        <Route index element={<Overview />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="tickets" element={<Tickets />} />
        <Route path="incidents" element={<IncidentList />} />
        <Route path="incidents/:id" element={<IncidentDetail />} />
        <Route path="endpoints" element={<Endpoints />} />
        <Route path="events" element={<Events />} />
        <Route path="identity" element={<Identity />} />
        <Route path="rules" element={<Rules />} />
        <Route path="audit" element={<Audit />} />
        <Route path="backups" element={<Backups />} />
        <Route path="terminal" element={<Terminal />} />
      </Route>
    </Routes>
  )
}
