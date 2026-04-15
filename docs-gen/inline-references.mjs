import { Converter, ReferenceReflection, DeclarationReflection } from 'typedoc';

/**
 * Registers a converter hook that inlines re-exported references so they
 * render as full documentation instead of links to the original module.
 *
 * @param {import('typedoc').Application} app
 */
export const registerInlineReferences = app => {
  app.converter.on(Converter.EVENT_RESOLVE_END, context => {
    const project = context.project;

    for (const ref of Object.values(project.reflections)) {
      if (!(ref instanceof ReferenceReflection)) continue;

      const target = ref.tryGetTargetReflectionDeep();
      if (!target || !(target instanceof DeclarationReflection)) continue;

      // Convert from ReferenceReflection to DeclarationReflection
      Object.setPrototypeOf(ref, DeclarationReflection.prototype);
      ref.variant = 'declaration';
      ref.kind = target.kind;
      ref.comment = target.comment?.clone();
      ref.type = target.type;
      ref.typeParameters = target.typeParameters;
      ref.signatures = target.signatures;
      ref.children = target.children;
      ref.groups = target.groups;
      ref.categories = target.categories;
      ref.indexSignatures = target.indexSignatures;
      ref.getSignature = target.getSignature;
      ref.setSignature = target.setSignature;
      ref.extendedTypes = target.extendedTypes;
      ref.implementedTypes = target.implementedTypes;
      ref.sources = target.sources;

      delete ref._target;
    }
  });
};
