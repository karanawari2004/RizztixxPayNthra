import axios from "axios";

const api = axios.create({
  baseURL: "https://rizzpaynthra.onrender.com/api",
  withCredentials: true,
});

export default api;
