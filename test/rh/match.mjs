// The real tool never finishes on some inputs (endless output or loops); the
// port must stop there too, with status 'hang' or 'truncated'.
export const matchesRh = (real, got) => real.status === 'hang'
  ? got.status === 'hang' || got.status === 'truncated'
  : got.status === real.status && got.stdout === real.stdout;
