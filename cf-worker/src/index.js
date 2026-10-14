import release from '../generated/release.js';
import { createHandler } from './router.js';

export default { fetch: createHandler(release) };
