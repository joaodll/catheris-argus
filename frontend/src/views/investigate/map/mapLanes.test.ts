import { describe, expect, it } from 'vitest'
import { hopColumns, hopLabel, layout, moveSelection, typeLabel, type LaidNode } from './mapLanes'

const n = (id: string, type: string | null, extra: Partial<LaidNode> = {}): LaidNode => ({ id, kind: 'resource', type, name: id, rank: 5, ...extra })

describe('Resource map columns', () => {
  it('labels types briefly', () => {
    expect(typeLabel('aws_lambda_function')).toBe('Lambda')
    expect(typeLabel('aws_ec2_target_group')).toBe('Target group')
    expect(typeLabel('aws_glue_job')).toBe('glue job')
  })

  it('counts hops from the focus: sources left, targets right, the nearest hop wins', () => {
    const edges = [
      { source: 'internet', target: 'www' },
      { source: 'www', target: 'app' },
      { source: 'app', target: 'alb' },
      { source: 'alb', target: 'tg' },
      { source: 'tg', target: 'i-1' },
      { source: 'internet', target: 'alb' },
    ]
    const cols = hopColumns(['internet', 'www', 'app', 'alb', 'tg', 'i-1'], edges, 'alb')
    expect(Object.fromEntries(cols)).toEqual({ alb: 0, tg: 1, 'i-1': 2, app: -1, internet: -1, www: -2 })
  })

  it('starts from what nothing points to without a focus, and is order-independent', () => {
    const edges = [
      { source: 'r1', target: 'r2' },
      { source: 'r2', target: 'lb' },
    ]
    const cols = hopColumns(['lb', 'r2', 'r1', 'lone'], edges, null)
    expect(Object.fromEntries(cols)).toEqual({ r1: 0, r2: 1, lb: 2, lone: 0 })
    expect(hopColumns(['r1', 'lone', 'lb', 'r2'], [...edges].reverse(), null)).toEqual(cols)
  })

  it('names the columns', () => {
    expect([-2, -1, 0, 1, 3].map((c) => hopLabel(c, true))).toEqual(['2 hops in', '1 hop in', 'Selected', '1 hop out', '3 hops out'])
    expect(hopLabel(0, false)).toBe('Step 1')
  })

  it('places columns left to right, hides empty ones, and centres the focus', () => {
    const nodes = [n('internet', null, { kind: 'internet' }), n('fn-b', 'aws_lambda_function'), n('fn-a', 'aws_lambda_function', { rank: 0 }), n('focus', 'aws_lambda_function'), n('role', 'aws_iam_role')]
    const edges = [
      { source: 'internet', target: 'focus' },
      { source: 'focus', target: 'fn-a' },
      { source: 'focus', target: 'fn-b' },
      { source: 'focus', target: 'role' },
    ]
    const { positions, lanes } = layout(nodes, edges, 'focus')
    expect(lanes.map((l) => [l.lane, l.label])).toEqual([
      ['hop--1', '1 hop in'],
      ['hop-0', 'Selected'],
      ['hop-1', '1 hop out'],
    ])
    expect(lanes.map((l) => l.x)).toEqual([0, 206, 412])
    expect(positions.get('focus')).toEqual({ x: 295, y: 0, lane: 'hop-0' })
    expect(positions.get('fn-a')!.y).toBe(-70) // worst first
    expect(positions.get('fn-b')!.y).toBe(0)
    expect(positions.get('role')!.y).toBe(70)
  })

  it('is the same every time for the same view', () => {
    const nodes = [n('b', 'aws_s3_bucket'), n('a', 'aws_s3_bucket'), n('c', 'aws_iam_role')]
    const edges = [{ source: 'c', target: 'a' }]
    expect(layout(nodes, edges, null)).toEqual(layout([...nodes].reverse(), edges, null))
  })

  it('moves the selection with the arrow keys', () => {
    const nodes = [n('internet', null, { kind: 'internet' }), n('f1', 'aws_lambda_function'), n('f2', 'aws_lambda_function'), n('role', 'aws_iam_role')]
    const edges = [
      { source: 'internet', target: 'f1' },
      { source: 'internet', target: 'f2' },
      { source: 'f1', target: 'role' },
    ]
    const { positions } = layout(nodes, edges, 'internet')
    expect(moveSelection(positions, null, 'down', 'f1')).toBe('f1')
    expect(moveSelection(positions, 'f1', 'down', 'f1')).toBe('f2')
    expect(moveSelection(positions, 'f2', 'down', 'f1')).toBe('f2')
    expect(moveSelection(positions, 'f1', 'left', 'f1')).toBe('internet')
    expect(moveSelection(positions, 'f1', 'right', 'f1')).toBe('role')
    expect(moveSelection(positions, 'role', 'right', 'f1')).toBe('role')
  })
})
