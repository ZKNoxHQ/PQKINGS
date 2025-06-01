import React from 'react'

interface IProps {
  className?: string
}

export default function Ellipsis({ className }: IProps) {
  return (
    <svg className={className} width="16" height="4" fill="none" viewBox="0 0 16 4">
      <circle cx="2" cy="2" r="2" fill="currentColor" />
      <circle cx="8" cy="2" r="2" fill="currentColor" />
      <circle cx="14" cy="2" r="2" fill="currentColor" />
    </svg>
  )
}
