// Memory harness: whether iterables left by `retain` get reclaimed. See `iterable-gc.ts`.

import { iterableGcTest } from "./iterable-gc";

iterableGcTest("retain");
