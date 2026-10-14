import {operatorRelay} from './relay.ts';
interface Bindings {OPERATOR_INGRESS_ENABLED?: string; OPERATOR_SERVICE?: Fetcher;}
export default {fetch(request: Request, env: Bindings): Promise<Response> {
 return operatorRelay({enabled: env.OPERATOR_INGRESS_ENABLED === 'true', service: env.OPERATOR_SERVICE}).fetch(request);
}};
