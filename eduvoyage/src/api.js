import axios from "axios";

export const api = axios.create({
  baseURL: "/api",          // uses Vite proxy
  withCredentials: true,    // keep true if you plan to use cookies; harmless otherwise
});
