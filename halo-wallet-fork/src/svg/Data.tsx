import React from 'react'

interface IProps {
  className?: string
}

export default function Data({ className }: IProps) {
  return (
    <svg className={className} width="24" height="24" fill="none" viewBox="0 0 24 24">
      <path
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="2"
        d="M9 8h6M9 12h6M9 16h6"
      />
      <rect width="16" height="18" x="4" y="3" stroke="currentColor" strokeWidth="2" rx="4" />
    </svg>
  )
}
