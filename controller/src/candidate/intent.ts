export interface PreparationIntent {
 readonly repositoryID: number;
 readonly baseSHA: string;
 readonly sourceSHA: string;
}

// Capture only validated primitive values before any asynchronous observation.
export function preparationIntent(value: unknown, repositoryID: number): Readonly<PreparationIntent> {
 if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype ||
     Object.keys(value).sort().join() !== 'baseSHA,repositoryID,sourceSHA') {
  throw Error('Invalid candidate preparation intent');
 }
 const {repositoryID: target, baseSHA, sourceSHA} = value as Record<string, unknown>;
 if (target !== repositoryID || ![baseSHA, sourceSHA].every(v => typeof v === 'string' && /^[a-f0-9]{40}$/.test(v))) {
  throw Error('Invalid candidate preparation intent');
 }
 return Object.freeze({repositoryID, baseSHA: baseSHA as string, sourceSHA: sourceSHA as string});
}
