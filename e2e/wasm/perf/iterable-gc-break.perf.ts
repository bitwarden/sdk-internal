// Memory harness: whether iterables left by `break` get reclaimed. See `iterable-gc.ts`.

import { iterableGcTest } from "./iterable-gc";

iterableGcTest("break");
