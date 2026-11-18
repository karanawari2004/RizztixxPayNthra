import axios from "axios";

const api = axios.create({
  baseURL: "https://payy-ml3f.onrender.com/api",
  withCredentials: true,
});

export default api;
