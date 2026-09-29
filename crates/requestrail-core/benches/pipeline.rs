use criterion::{black_box, criterion_group, criterion_main, Criterion};
use requestrail_core::{Context, Pipeline, Verdict};

fn bench_empty_pipeline(c: &mut Criterion) {
    let pipeline = Pipeline::new();
    let ctx = Context::new("test body");

    c.bench_function("empty pipeline", |b| {
        b.iter(|| pipeline.evaluate(black_box(ctx.clone())))
    });
}

criterion_group!(benches, bench_empty_pipeline);
criterion_main!(benches);
