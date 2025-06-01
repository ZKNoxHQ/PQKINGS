import React from 'react'
import classNames from 'classnames'

interface IProps {
  className?: string
  children?: React.ReactNode
  fullWidth?: boolean
  icon?: React.ReactNode
  onClick(): void
}

export default function Button({ icon, children, className, fullWidth, onClick }: IProps) {
  return (
    <button
      onClick={onClick}
      className={classNames('button', { 'button--has-icon': icon, 'button--full-width': fullWidth }, className)}
    >
      <span>{children}</span>
      {icon && <>{icon}</>}
    </button>
  )
}
