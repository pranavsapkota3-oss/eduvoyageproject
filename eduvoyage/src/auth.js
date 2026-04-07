export const isLoggedIn = () => {
  return !!localStorage.getItem("token");
};

export const getUser = () => {
  const raw = localStorage.getItem("user");
  return raw ? JSON.parse(raw) : null;
};
