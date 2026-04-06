import React from "react";
import { Routes, Route, NavLink } from "react-router-dom";
import DetectorPage from "./pages/DetectorPage";
import MethodologyPage from "./pages/MethodologyPage";
import styles from "./App.module.css";

export default function App() {
  return (
    <div className={styles.shell}>
      <header className={styles.header}>
        <div className={styles.logo}>
          <span className={styles.shield}>⬡</span>
          <span>PhishGuard</span>
        </div>
        <nav className={styles.nav}>
          <NavLink
            to="/"
            end
            className={({ isActive }) =>
              isActive ? `${styles.link} ${styles.active}` : styles.link
            }
          >
            Detector
          </NavLink>
          <NavLink
            to="/methodology"
            className={({ isActive }) =>
              isActive ? `${styles.link} ${styles.active}` : styles.link
            }
          >
            Methodology
          </NavLink>
        </nav>
      </header>

      <main className={styles.main}>
        <Routes>
          <Route path="/" element={<DetectorPage />} />
          <Route path="/methodology" element={<MethodologyPage />} />
        </Routes>
      </main>

      <footer className={styles.footer}>
        <span>PhishGuard — ML URL Risk Analyser</span>
      </footer>
    </div>
  );
}
