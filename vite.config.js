import { defineConfig } from "vite";

// The Streamlit dashboard keeps running on :8501 (streamlit run dashboard.py).
// Vite only serves the launcher page on :5173.
export default defineConfig({
  server: { port: 5173, open: true },
  preview: { port: 4173 },
});
