import React from 'react'
import classNames from 'classnames'

interface IProps {
  className?: string
  children?: React.ReactNode
}

export default function Wrapper({ children, className }: IProps) {
  return <div className={classNames('wrapper', className)}>{children}</div>
}
