import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";
import { componentTagger } from "lovable-tagger";

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => ({
  server: {
  host: true,       // equivale a 0.0.0.0
  port: 8080,
  strictPort: true, // evita fallback a otro puerto
  watch: {
    usePolling: true // necesario en Docker para detectar cambios
  }
},

  plugins: [react(), mode === "development" && componentTagger()].filter(Boolean),
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
}));
