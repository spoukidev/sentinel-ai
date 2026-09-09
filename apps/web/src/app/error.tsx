"use client";
export default function ErrorBoundary({ reset }: { reset: () => void }) {
  return (
    <main className="error-page">
      <h1>Something went wrong</h1>
      <p>Reload the workspace to try again. Your saved data is preserved.</p>
      <button onClick={reset}>Try again</button>
    </main>
  );
}
