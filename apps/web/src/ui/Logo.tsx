export function Logo({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true" focusable="false">
      <path
        d="M16 2 4 7v8c0 7.2 5.1 13.4 12 15 6.9-1.6 12-7.8 12-15V7z"
        fill="#0d1424"
        stroke="#4cc3e6"
        strokeWidth="2"
      />
      <path
        d="M11 16.5l3.5 3.5L21 13"
        fill="none"
        stroke="#9d8cf8"
        strokeWidth="2.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
