import React from 'react'

interface IProps {
  className?: string
}

export default function Scan({ className }: IProps) {
  return (
    <svg className={className} width="24" height="24" fill="none" viewBox="0 0 24 24">
      <path
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="2"
        d="M3 9V5c0-1.1.9-2 2-2h4M15 3h4c1.1 0 2 .9 2 2v4M21 15v4c0 1.1-.9 2-2 2h-4M9 21H5c-1.1 0-2-.9-2-2v-4"
      />
      <path stroke="url(#a)" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M16 12H8" />
      <defs>
        <linearGradient id="a" x1="16" x2="8" y1="12" y2="12" gradientUnits="userSpaceOnUse">
          <stop stopColor="currentColor" />
          <stop offset="1" stopColor="currentColor" stopOpacity="0" />
        </linearGradient>
      </defs>
    </svg>
  )
}
