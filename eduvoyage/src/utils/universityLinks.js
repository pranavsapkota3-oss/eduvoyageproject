const normalizeUrl = (url) => {
  if (!url) return "";
  const trimmed = String(url).trim();
  if (!trimmed) return "";
  return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
};

export const getUniversityWebsiteUrl = (university) => {
  const directUrl = normalizeUrl(university?.website);
  if (directUrl) return directUrl;

  const query = [university?.name, university?.country, "official website"]
    .filter(Boolean)
    .join(" ");

  return `https://www.google.com/search?q=${encodeURIComponent(query)}`;
};

export const getUniversityApplyUrl = (university) => {
  const directUrl = normalizeUrl(university?.website);
  if (directUrl) {
    return directUrl.includes("/apply") || directUrl.includes("/admissions")
      ? directUrl
      : `${directUrl.replace(/\/$/, "")}/admissions`;
  }

  const query = [university?.name, university?.country, "apply international students"]
    .filter(Boolean)
    .join(" ");

  return `https://www.google.com/search?q=${encodeURIComponent(query)}`;
};
