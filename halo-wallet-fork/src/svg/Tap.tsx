import React from 'react'

interface IProps {
  className?: string
}

export default function Tap({ className }: IProps) {
  return (
    <svg className={className} width="24" height="24" fill="none" viewBox="0 0 24 24">
      <path
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="2"
        d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM20.35 15.35c.42-1.04.65-2.16.65-3.35a9 9 0 0 0-9-9c-1.18 0-2.31.23-3.35.65M3.65 8.65A8.885 8.885 0 0 0 3 12a9 9 0 0 0 9 9c1.18 0 2.31-.23 3.35-.65"
      />
    </svg>
  )
}
