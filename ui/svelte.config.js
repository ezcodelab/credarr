// Runes are the mode every component here is written in; pin it so a
// component that slips back to legacy syntax fails the build instead of
// silently taking the other compiler path.
export default { compilerOptions: { runes: true } };
